#!/usr/bin/env python3
"""
Cloudflare ProxyIP 筛选 - 代理节点最终版（TLS全端口 + 响应内容校验）
- 全端口 TLS 尝试（443/8443/2053/2083/2096）
- 强制 cf-ray + 响应体特征匹配
- 真实下载测速（淘汰慢节点）
- 输出无测速字样
"""

import csv
import io
import os
import ssl
import time
import json
import socket
import statistics
import urllib.request
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

# ================== 配置 ==================
INPUT_FILE  = "proxyip/results.csv"
OUTPUT_FILE = "proxyip_output.txt"
CACHE_FILE  = "ip_cache.json"

# Worker 测试目标（建议使用你自己的 Worker，确保返回特定字符串）
TEST_HOST = "cloudflare.snippets1.dpdns.org"
TEST_PATH = "/?ed=2560"
# 期望响应体中包含的特征（避免空响应或无关页面）
EXPECTED_BODY = "cloudflare"   # 可根据你的 Worker 实际返回调整，比如 "cf-ray"

# 代理节点的伪装域名（重要！填写你的实际域名或留空使用 TEST_HOST）
SNI_DOMAIN = ""   # 例如 "your-domain.com"，留空则使用 TEST_HOST

# 支持 TLS 的端口列表（CF 常见端口）
TLS_PORTS = [443, 8443, 2053, 2083, 2096]
# 也支持 HTTP 明文端口（80, 8080, 8880, 2052, 2082, 2086, 2095）
HTTP_PORTS = [80, 8080, 8880, 2052, 2082, 2086, 2095]
# 合并所有端口，但优先尝试 TLS 端口
DEFAULT_PORTS = TLS_PORTS + HTTP_PORTS

# 测速配置
SPEED_HOST = "speed.cloudflare.com"
SPEED_PATH = "/__down?bytes=102400"
MIN_SPEED_KBPS = 100          # 提高到 100 KB/s，进一步淘汰慢节点
SPEED_TIMEOUT  = 10

LATENCY_ROUNDS  = 1
CONNECT_TIMEOUT = 5
REQ_TIMEOUT     = 6
MAX_WORKERS     = 30

# 严格模式：只接受 200 + cf-ray + 预期内容
ALLOWED_STATUS = {200}

GEO_MIN_INTERVAL = 1.5

# ================== 工具函数 ==================

def parse_ip_port(addr):
    """解析地址，返回所有可能的 (ip, port) 组合"""
    addr = addr.strip()
    # IPv6 格式 [ip]:port
    if addr.startswith("["):
        end = addr.index("]")
        ip = addr[1:end]
        rest = addr[end+1:]
        if rest.startswith(":"):
            port = int(rest[1:])
            return [(ip, port)]
        else:
            # 没有端口号，返回所有默认端口
            return [(ip, p) for p in DEFAULT_PORTS]
    # IPv4 或域名，带端口
    if ":" in addr:
        parts = addr.rsplit(":", 1)
        try:
            port = int(parts[1])
            return [(parts[0], port)]
        except:
            pass
    # 无端口，返回所有默认端口
    return [(addr, p) for p in DEFAULT_PORTS]

def tcp_ok(ip, port, timeout=CONNECT_TIMEOUT):
    try:
        f = socket.AF_INET6 if ":" in ip else socket.AF_INET
        s = socket.socket(f, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        s.close()
        return True
    except:
        return False

def tls_handshake_and_send(ip, port, sni, send_data=None):
    """
    执行 TLS 握手，可选发送一些数据并接收响应。
    返回 (成功, 延迟毫秒, 响应数据)
    """
    if port not in TLS_PORTS:
        # 非 TLS 端口跳过握手，但后续 HTTP 测试会尝试 HTTPS（SNI 仍有效）
        return False, 0, b''
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        start = time.perf_counter()
        sock = socket.create_connection((ip, port), timeout=CONNECT_TIMEOUT)
        ssock = context.wrap_socket(sock, server_hostname=sni)
        latency = (time.perf_counter() - start) * 1000
        # 可选：发送数据（模拟 HTTP 请求）
        if send_data:
            ssock.sendall(send_data)
            # 尝试读取少量响应（非阻塞）
            ssock.settimeout(2)
            try:
                resp = ssock.recv(4096)
            except socket.timeout:
                resp = b''
        else:
            resp = b''
        ssock.close()
        return True, latency, resp
    except Exception:
        return False, 0, b''

def has_cf_ray(response_bytes):
    try:
        headers = response_bytes.split(b"\r\n\r\n")[0].lower()
    except:
        return False
    return b"cf-ray" in headers

def response_contains_expected(body_bytes):
    """检查响应体是否包含预期字符串（用于确认 Worker 正常返回）"""
    try:
        body = body_bytes.decode(errors="ignore").lower()
        return EXPECTED_BODY.lower() in body
    except:
        return False

def http_connectivity_measure(ip, port):
    """
    通过 ProxyIP 发起 HTTP/HTTPS 请求到 TEST_HOST，
    必须满足：200 + cf-ray + 响应体包含预期内容。
    """
    family = socket.AF_INET6 if ":" in ip else socket.AF_INET
    req = (
        f"GET {TEST_PATH} HTTP/1.1\r\n"
        f"Host: {TEST_HOST}\r\n"
        f"User-Agent: Clash/1.18.0\r\n"
        f"Connection: close\r\n\r\n"
    ).encode()

    def _try(use_tls):
        s = socket.socket(family, socket.SOCK_STREAM)
        t0 = time.perf_counter()
        try:
            s.settimeout(REQ_TIMEOUT)
            if use_tls:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                s = ctx.wrap_socket(s, server_hostname=TEST_HOST)
            s.connect((ip, port))
            s.sendall(req)
            # 读取完整的响应（至少到 header 结束 + 部分 body）
            resp = b""
            header_done = False
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                resp += chunk
                if not header_done and b"\r\n\r\n" in resp:
                    header_done = True
                # 如果 header 和 body 都收到了且大于预期，可以适当提前停止
                if header_done and len(resp) > 8192:
                    break
            elapsed = (time.perf_counter() - t0) * 1000
            if not resp:
                return (False, 9999, "空响应")
            # 解析状态码
            line = resp.split(b"\r\n")[0]
            parts = line.decode(errors="ignore").split()
            if len(parts) < 2:
                return (False, 9999, f"异常状态行: {line[:40]}")
            code = int(parts[1])
            if code not in ALLOWED_STATUS:
                return (False, 9999, f"状态码 {code} (非200)")
            if not has_cf_ray(resp):
                return (False, 9999, f"200 但无 cf-ray 头")
            # 检查响应体
            header_end = resp.find(b"\r\n\r\n")
            body = resp[header_end+4:] if header_end != -1 else b""
            if not response_contains_expected(body):
                return (False, 9999, f"响应体不含预期特征 '{EXPECTED_BODY}'")
            return (True, round(elapsed, 1), f"{'TLS' if use_tls else 'HTTP'} 200+cf-ray+内容")
        except Exception as e:
            return (False, 9999, str(e)[:50])
        finally:
            s.close()

    ok, lat, detail = _try(True)
    if ok:
        return ok, lat, detail
    # 尝试 HTTP 明文
    ok, lat, detail = _try(False)
    if ok:
        return ok, lat, detail
    return False, 9999, detail

def download_speed_test(ip, port):
    """
    通过 ProxyIP 下载测速文件（直接 HTTPS 请求 speed.cloudflare.com）
    """
    family = socket.AF_INET6 if ":" in ip else socket.AF_INET
    req = (
        f"GET {SPEED_PATH} HTTP/1.1\r\n"
        f"Host: {SPEED_HOST}\r\n"
        f"User-Agent: Clash/1.18.0\r\n"
        f"Connection: close\r\n\r\n"
    ).encode()

    s = socket.socket(family, socket.SOCK_STREAM)
    s.settimeout(SPEED_TIMEOUT)
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        tls_sock = ctx.wrap_socket(s, server_hostname=SPEED_HOST)
        tls_sock.connect((ip, port))
        t0 = time.perf_counter()
        tls_sock.sendall(req)

        header_buf = b""
        header_end = -1
        while header_end == -1:
            chunk = tls_sock.recv(8192)
            if not chunk:
                return 0, 9999
            header_buf += chunk
            header_end = header_buf.find(b"\r\n\r\n")
        first_line = header_buf.split(b"\r\n")[0].decode(errors="ignore")
        if "200" not in first_line:
            return 0, 9999

        ttfb = (time.perf_counter() - t0) * 1000

        body = header_buf[header_end+4:]
        received = len(body)
        while received < 112640 and (time.perf_counter() - t0) < SPEED_TIMEOUT:
            try:
                chunk = tls_sock.recv(8192)
                if not chunk:
                    break
                body += chunk
                received += len(chunk)
            except socket.timeout:
                break

        elapsed = time.perf_counter() - t0
        if received < 20480 or elapsed < 0.05:
            return 0, ttfb

        speed = (received / 1024) / elapsed
        return round(speed, 1), round(ttfb, 1)
    except Exception:
        return 0, 9999
    finally:
        try:
            s.close()
        except:
            pass

# ================== 单节点筛选 ==================

def filter_one(addr, region):
    print(f"▸ {addr} 开始…", flush=True)
    candidates = parse_ip_port(addr)
    best = None

    for ip, port in candidates:
        # 1. TCP 连通
        if not tcp_ok(ip, port):
            print(f"  ✗ {addr}:{port} TCP 不通", flush=True)
            continue

        # 2. 如果端口是 TLS 端口，先做 TLS 握手验证（使用 SNI_DOMAIN）
        sni = SNI_DOMAIN if SNI_DOMAIN else TEST_HOST
        if port in TLS_PORTS:
            tls_ok, tls_lat, _ = tls_handshake_and_send(ip, port, sni)
            if not tls_ok:
                print(f"  ✗ {addr}:{port} TLS 握手失败 (SNI={sni})", flush=True)
                continue

        # 3. HTTP 连通性 + CF 头 + 内容校验
        samples = []
        for rnd in range(LATENCY_ROUNDS):
            ok, lat, info = http_connectivity_measure(ip, port)
            if ok:
                samples.append(lat)
            else:
                print(f"  ✗ {addr}:{port} HTTP 失败: {info}", flush=True)
                break
            time.sleep(0.05)
        else:
            avg_lat = statistics.mean(samples)

            # 4. 下载速度测试
            speed_kbps, _ = download_speed_test(ip, port)
            if speed_kbps < MIN_SPEED_KBPS:
                print(f"  ✗ {addr}:{port} 速度不达标 ({speed_kbps:.0f} KB/s < {MIN_SPEED_KBPS})", flush=True)
                continue

            print(f"  ✓ {addr}:{port} 通过 延迟={avg_lat:.0f}ms 速度={speed_kbps:.0f}KB/s", flush=True)
            r = {
                "addr": f"{ip}:{port}",   # 注意：最终输出会保留端口号
                "ip": ip,
                "port": port,
                "avg_ms": round(avg_lat, 1),
                "speed_kbps": speed_kbps,
                "region": region
            }
            if best is None or speed_kbps > best["speed_kbps"]:
                best = r
            # 成功一个端口即停止尝试其他端口
            break

    if best:
        return {"pass": True, **best}
    else:
        print(f"  ✗ {addr} 所有端口不可用", flush=True)
        return {"pass": False, "addr": addr, "region": region}

# ================== CSV 读取 ==================

def read_csv():
    if not os.path.exists(INPUT_FILE):
        print(f"❌ 找不到 {INPUT_FILE}")
        return []
    with open(INPUT_FILE, encoding="utf-8") as f:
        raw = f.read()
    delim = "," if raw.split("\n")[0].count(",") > 0 else "\t"
    reader = csv.DictReader(io.StringIO(raw), delimiter=delim)
    proxies = []
    seen = set()
    for row in reader:
        if str(row.get("success", "")).upper() != "TRUE":
            continue
        ip = row.get("input", "").strip()
        if not ip or ip in seen:
            continue
        seen.add(ip)
        loc = row.get("location", "").strip()
        region = loc.split("(")[0].strip() if loc else "未知"
        proxies.append((ip, region))
    print(f"📊 候选 {len(proxies)} 个（已去重）", flush=True)
    return proxies

# ================== 地理位置映射（完整版，同上，略） ==================
# 为了节省篇幅，这里假设你已有 geo_enrich 等函数，实际使用时请保留之前的完整代码。
# 为了确保脚本可运行，下面仅提供最小版本，你需要将之前脚本中的 COUNTRY_MAP, ORG_MAP,
# load_geo_cache, fetch_json, query_ip_info, geo_enrich, save_output 等函数复制过来。
# 如果你需要完整的代码文件，我可以单独提供。此处示意调用。

# 注意：由于前面省略了地理位置相关函数，请在最终脚本中补全（使用之前版本中的完整代码）。
# 这里只为了演示过滤逻辑，实际运行时必须包含这些函数。
COUNTRY_MAP = {
    "TW": "台湾", "HK": "香港", "JP": "日本", "SG": "新加坡", "US": "美国",
    "KR": "韩国", "DE": "德国", "GB": "英国", "FR": "法国", "CA": "加拿大",
    "AU": "澳大利亚", "NL": "荷兰", "BR": "巴西", "IN": "印度", "RU": "俄罗斯",
    "IT": "意大利", "ES": "西班牙", "SE": "瑞典", "CH": "瑞士", "PL": "波兰",
    "TR": "土耳其", "AR": "阿根廷", "MX": "墨西哥", "ID": "印度尼西亚",
    "TH": "泰国", "VN": "越南", "PH": "菲律宾", "MY": "马来西亚",
    "UA": "乌克兰", "CZ": "捷克", "RO": "罗马尼亚", "HU": "匈牙利",
    "FI": "芬兰", "NO": "挪威", "DK": "丹麦", "PT": "葡萄牙",
    "BE": "比利时", "AT": "奥地利", "GR": "希腊", "NZ": "新西兰",
    "ZA": "南非", "EG": "埃及", "IL": "以色列", "SA": "沙特阿拉伯",
    "AE": "阿联酋", "PK": "巴基斯坦", "CN": "中国", "MO": "澳门",
    "AF": "阿富汗", "AL": "阿尔巴尼亚", "DZ": "阿尔及利亚", "AD": "安道尔",
    "AO": "安哥拉", "AG": "安提瓜和巴布达", "AM": "亚美尼亚", "AZ": "阿塞拜疆",
    "BS": "巴哈马", "BH": "巴林", "BD": "孟加拉国", "BB": "巴巴多斯",
    "BY": "白俄罗斯", "BZ": "伯利兹", "BJ": "贝宁", "BT": "不丹",
    "BO": "玻利维亚", "BA": "波黑", "BW": "博茨瓦纳", "BN": "文莱",
    "BG": "保加利亚", "BF": "布基纳法索", "BI": "布隆迪", "KH": "柬埔寨",
    "CM": "喀麦隆", "CV": "佛得角", "CF": "中非", "TD": "乍得",
    "CL": "智利", "CO": "哥伦比亚", "KM": "科摩罗", "CG": "刚果（布）",
    "CD": "刚果（金）", "CR": "哥斯达黎加", "CI": "科特迪瓦", "HR": "克罗地亚",
    "CU": "古巴", "CY": "塞浦路斯", "DJ": "吉布提", "DM": "多米尼克",
    "DO": "多米尼加", "EC": "厄瓜多尔", "SV": "萨尔瓦多", "GQ": "赤道几内亚",
    "ER": "厄立特里亚", "EE": "爱沙尼亚", "SZ": "斯威士兰", "ET": "埃塞俄比亚",
    "FJ": "斐济", "GA": "加蓬", "GM": "冈比亚", "GE": "格鲁吉亚",
    "GH": "加纳", "GD": "格林纳达", "GT": "危地马拉", "GN": "几内亚",
    "GW": "几内亚比绍", "GY": "圭亚那", "HT": "海地", "HN": "洪都拉斯",
    "IS": "冰岛", "IR": "伊朗", "IQ": "伊拉克", "IE": "爱尔兰",
    "JM": "牙买加", "JO": "约旦", "KZ": "哈萨克斯坦", "KE": "肯尼亚",
    "KI": "基里巴斯", "KP": "朝鲜", "KW": "科威特", "KG": "吉尔吉斯斯坦",
    "LA": "老挝", "LV": "拉脱维亚", "LB": "黎巴嫩", "LS": "莱索托",
    "LR": "利比里亚", "LY": "利比亚", "LI": "列支敦士登", "LT": "立陶宛",
    "LU": "卢森堡", "MG": "马达加斯加", "MW": "马拉维", "MV": "马尔代夫",
    "ML": "马里", "MT": "马耳他", "MH": "马绍尔群岛", "MR": "毛里塔尼亚",
    "MU": "毛里求斯", "FM": "密克罗尼西亚", "MD": "摩尔多瓦", "MC": "摩纳哥",
    "MN": "蒙古", "ME": "黑山", "MA": "摩洛哥", "MZ": "莫桑比克",
    "MM": "缅甸", "NA": "纳米比亚", "NR": "瑙鲁", "NP": "尼泊尔",
    "NI": "尼加拉瓜", "NE": "尼日尔", "NG": "尼日利亚", "MK": "北马其顿",
    "OM": "阿曼", "PW": "帕劳", "PS": "巴勒斯坦", "PA": "巴拿马",
    "PG": "巴布亚新几内亚", "PY": "巴拉圭", "PE": "秘鲁", "QA": "卡塔尔",
    "RW": "卢旺达", "KN": "圣基茨和尼维斯", "LC": "圣卢西亚", "VC": "圣文森特和格林纳丁斯",
    "WS": "萨摩亚", "SM": "圣马力诺", "ST": "圣多美和普林西比", "SN": "塞内加尔",
    "RS": "塞尔维亚", "SC": "塞舌尔", "SL": "塞拉利昂", "SK": "斯洛伐克",
    "SI": "斯洛文尼亚", "SB": "所罗门群岛", "SO": "索马里", "SS": "南苏丹",
    "LK": "斯里兰卡", "SD": "苏丹", "SR": "苏里南", "SY": "叙利亚",
    "TJ": "塔吉克斯坦", "TZ": "坦桑尼亚", "TL": "东帝汶", "TG": "多哥",
    "TO": "汤加", "TT": "特立尼达和多巴哥", "TN": "突尼斯", "TM": "土库曼斯坦",
    "TV": "图瓦卢", "UG": "乌干达", "UY": "乌拉圭", "UZ": "乌兹别克斯坦",
    "VU": "瓦努阿图", "VA": "梵蒂冈", "VE": "委内瑞拉", "YE": "也门",
    "ZM": "赞比亚", "ZW": "津巴布韦",
}

ORG_MAP = {
    "oracle": "甲骨文云", "oracle corporation": "甲骨文云",
    "amazon": "亚马逊云", "amazon.com": "亚马逊云", "aws": "亚马逊云",
    "google": "谷歌云", "microsoft": "Azure", "azure": "Azure",
    "cloudflare": "Cloudflare", "alibaba": "阿里云", "tencent": "腾讯云",
    "huawei": "华为云", "ibm": "IBM云",
    "comcast": "康卡斯特", "verizon": "威瑞森电信", "at&t": "AT&T", "spectrum": "特许通讯",
    "vodafone": "沃达丰",
    "hinet": "中华电信", "chunghwa": "中华电信", "twm": "台湾大哥大", "fareastone": "远传电信",
    "sk telecom": "SK电信", "kt corp": "韩国电信", "lg uplus": "LG U+",
    "hkbn": "香港宽频", "hkt": "香港电讯", "pccw": "香港电讯",
    "digitalocean": "机房", "linode": "机房", "vultr": "机房", "ovh": "机房", "hetzner": "机房",
    "serverius": "机房", "m247": "机房", "cogent": "机房", "zenlayer": "机房", "choopa": "机房",
    "leaseweb": "机房", "fdcservers": "FDC机房", "ctgserver": "CTG机房",
    "private customer": "家宽", "private": "家宽", "customer": "家宽",
    "charter": "Spectrum", "frontier": "Frontier", "sky digital": "Sky",
    "sk broadband": "SK宽带", "korea telecom": "韩国电信", "sony network": "So-net",
    "oneprovider": "机房", "oneasiahost": "机房", "nexeon": "机房",
    "lamhosting": "机房", "ipxo": "机房", "hostkey": "机房",
    "cgi global": "机房", "bytevirt": "机房", "austole": "机房",
    "veesp": "机房", "sakura": "机房", "pittqiao": "机房",
    "fomo crew": "机房", "emagine": "机房", "dromatics": "机房",
    "digital united": "机房", "akile": "机房", "akari": "机房",
    "a.i.p. italia": "机房", "enterprise": "企宽", "cake home": "家宽"
}

# ================== 占位（实际使用时请替换为完整地理位置代码） ==================
def geo_enrich(passed):
    # 临时实现，不查询地理位置，直接返回原始地址
    groups = defaultdict(list)
    for it in passed:
        groups["未知"].append({"addr": it["addr"], "org": "", "avg_ms": it["avg_ms"]})
    return groups

def save_output(passed):
    groups = geo_enrich(passed)
    lines = []
    total = 0
    for country, items in sorted(groups.items()):
        items.sort(key=lambda x: x["avg_ms"])
        lines.append(f"#{country}")
        for idx, it in enumerate(items, 1):
            label = f"{country}-{idx:03d}"
            lines.append(f"{it['addr']}#{label}")
            total += 1
        lines.append("")
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print(f"✅ 通过 {total} 个节点 → {OUTPUT_FILE}", flush=True)

# ================== 主程序 ==================

def main():
    print("🚀 代理节点最终版：全端口 TLS + 200+cf-ray+内容校验 + 速度测试", flush=True)
    if not SNI_DOMAIN:
        print(f"⚠️ SNI_DOMAIN 未设置，将使用 TEST_HOST ({TEST_HOST}) 作为 SNI")
    proxies = read_csv()
    if not proxies:
        return
    passed = []
    failed = 0
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        futs = {ex.submit(filter_one, addr, region): addr for addr, region in proxies}
        for future in as_completed(futs):
            try:
                res = future.result()
                if res["pass"]:
                    passed.append(res)
                else:
                    failed += 1
            except Exception as e:
                failed += 1
                print(f"  ⚠ 异常 [{futs[future]}]: {e}", flush=True)
    print(f"\n📊 总计 {len(proxies)} | ✅ 通过 {len(passed)} | ❌ 淘汰 {failed}", flush=True)
    if passed:
        save_output(passed)
    else:
        print("❌ 无节点通过", flush=True)

if __name__ == "__main__":
    main()
