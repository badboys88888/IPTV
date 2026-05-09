#!/usr/bin/env python3
"""
Cloudflare ProxyIP 筛选 - 严格模式（真实模拟 + CF-RAY 强制校验）
- HTTP 连通性（必须 200 + cf-ray）
- 直接 HTTPS 下载测速（必须高于最低速度）
- 自动查询地理位置（限速防封）
- 输出仅国家/运营商标签，无测速文字
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

# 测试目标（建议替换为你自己的 Worker 或 Cloudflare 上任意启用了代理的域名）
TEST_HOST = "cloudflare.snippets1.dpdns.org"
TEST_PATH = "/?ed=2560"          # 路径参数有利于区分缓存

# 测速目标（Cloudflare 官方测速文件，100KB）
SPEED_HOST = "speed.cloudflare.com"
SPEED_PORT = 443
SPEED_PATH = "/__down?bytes=102400"
MIN_SPEED_KBPS = 50
SPEED_TIMEOUT  = 10

LATENCY_ROUNDS  = 1
CONNECT_TIMEOUT = 5
REQ_TIMEOUT     = 6
MAX_WORKERS     = 30
DEFAULT_PORTS   = [443, 80]

# 严格模式：只接受 200，且必须有 cf-ray 头
ALLOWED_STATUS = {200}

GEO_MIN_INTERVAL = 1.5

# ================== 工具函数 ==================

def parse_ip_port(addr):
    addr = addr.strip()
    if addr.startswith("["):
        end = addr.index("]")
        ip = addr[1:end]
        rest = addr[end+1:]
        port = int(rest[1:]) if rest.startswith(":") else 443
        return [(ip, port)]
    if ":" in addr:
        parts = addr.rsplit(":", 1)
        try:
            return [(parts[0], int(parts[1]))]
        except ValueError:
            pass
    return [(addr, p) for p in DEFAULT_PORTS]

def tcp_ok(ip, port):
    try:
        f = socket.AF_INET6 if ":" in ip else socket.AF_INET
        s = socket.socket(f, socket.SOCK_STREAM)
        s.settimeout(CONNECT_TIMEOUT)
        s.connect((ip, port))
        s.close()
        return True
    except:
        return False

def has_cf_ray(response_bytes):
    """检查响应头中是否包含 cf-ray (Cloudflare 核心标识)"""
    try:
        headers = response_bytes.split(b"\r\n\r\n")[0].lower()
    except:
        return False
    return b"cf-ray" in headers

def http_connectivity_measure(ip, port):
    """
    通过 ProxyIP 发起真正的 HTTP/HTTPS 请求到 TEST_HOST，
    必须返回 200 状态码且包含 cf-ray 头。
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
                # 关键：SNI 设置为 TEST_HOST，模拟真实客户端
                s = ctx.wrap_socket(s, server_hostname=TEST_HOST)
            s.connect((ip, port))
            s.sendall(req)
            resp = b""
            while b"\r\n\r\n" not in resp:
                chunk = s.recv(1024)
                if not chunk:
                    break
                resp += chunk
            elapsed = (time.perf_counter() - t0) * 1000
            if not resp:
                return (False, 9999, "空响应")
            # 解析状态码
            line = resp.split(b"\r\n")[0]
            parts = line.decode(errors="ignore").split()
            if len(parts) < 2:
                return (False, 9999, f"异常状态行: {line[:40]}")
            code = int(parts[1])
            # 严格模式：只接受 200，且必须有 cf-ray
            if code not in ALLOWED_STATUS:
                return (False, 9999, f"状态码 {code} (非200)")
            if not has_cf_ray(resp):
                return (False, 9999, f"200 但无 cf-ray 头")
            return (True, round(elapsed, 1), f"{'TLS' if use_tls else 'HTTP'} 200+cf-ray")
        except Exception as e:
            return (False, 9999, str(e)[:50])
        finally:
            s.close()

    ok, lat, detail = _try(True)
    if ok:
        return ok, lat, detail
    # 重试 HTTP（80端口）仅用于测试，但对现代代理很少有用，可保留
    ok, lat, detail = _try(False)
    if ok:
        return ok, lat, detail
    return False, 9999, detail

def download_speed_test(ip, port):
    """
    通过 ProxyIP 直接连接 speed.cloudflare.com:443 下载测速文件。
    注意：这个测试独立于上面的连通性测试，用于淘汰速度慢的节点。
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
        if not tcp_ok(ip, port):
            print(f"  ✗ {addr} TCP 不通", flush=True)
            continue

        # HTTP 连通性 + CF-RAY 强制检查
        samples = []
        for rnd in range(LATENCY_ROUNDS):
            ok, lat, info = http_connectivity_measure(ip, port)
            if ok:
                samples.append(lat)
            else:
                print(f"  ✗ {addr} HTTP 失败: {info}", flush=True)
                break
            time.sleep(0.05)
        else:
            avg_lat = statistics.mean(samples)

            # 速度测试
            speed_kbps, _ = download_speed_test(ip, port)
            if speed_kbps < MIN_SPEED_KBPS:
                print(f"  ✗ {addr} 速度不达标 ({speed_kbps:.0f} KB/s < {MIN_SPEED_KBPS})", flush=True)
                continue

            print(f"  ✓ {addr} 通过 延迟={avg_lat:.0f}ms 速度={speed_kbps:.0f}KB/s", flush=True)
            r = {
                "addr": addr, "ip": ip, "port": port,
                "avg_ms": round(avg_lat, 1),
                "speed_kbps": speed_kbps,
                "region": region
            }
            if best is None or speed_kbps > best["speed_kbps"]:
                best = r
            break   # 成功一个端口即停止

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

# ================== 地理位置映射（完整版） ==================

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

def org_cn(org):
    if not org: return "未知"
    lo = org.lower()
    for k, v in ORG_MAP.items():
        if k in lo:
            return v
    return org

def load_geo_cache():
    try:
        with open(CACHE_FILE, encoding="utf-8") as f:
            return json.load(f)
    except:
        return {}

def save_geo_cache(cache):
    with open(CACHE_FILE, "w", encoding="utf-8") as f:
        json.dump(cache, f, ensure_ascii=False, indent=2)

def fetch_json(url, timeout=8):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode())
    except Exception:
        return None

def query_ip_info(ip_str, cache, lock, last_req):
    ip_only = ip_str.split(":")[0]
    with lock:
        if ip_only in cache:
            return ip_only, cache[ip_only]["country"], cache[ip_only]["org"]
        now = time.time()
        wait = last_req[0] + GEO_MIN_INTERVAL - now
        if wait > 0:
            time.sleep(wait)
        last_req[0] = time.time()

    country, org = "未知", "未知"
    data = fetch_json(f"https://ipwho.is/{ip_only}")
    if data and data.get("success"):
        cc = data.get("country_code", "")
        country = COUNTRY_MAP.get(cc, data.get("country", cc or "未知"))
        org = org_cn(data.get("connection", {}).get("isp", ""))
    if country == "未知":
        data = fetch_json(f"https://freeipapi.com/api/json/{ip_only}")
        if data:
            cc = data.get("countryCode", "")
            country = COUNTRY_MAP.get(cc, data.get("countryName", cc or "未知"))
            org = org_cn(data.get("asnOrganization", ""))
    if country == "未知":
        data = fetch_json(f"http://ip-api.com/json/{ip_only}?fields=status,countryCode,isp")
        if data and data.get("status") == "success":
            cc = data.get("countryCode", "")
            country = COUNTRY_MAP.get(cc, cc or "未知")
            org = org_cn(data.get("isp", ""))
    with lock:
        cache[ip_only] = {"country": country, "org": org}
    return ip_only, country, org

def geo_enrich(passed):
    cache = load_geo_cache()
    lock = threading.Lock()
    last_req = [0.0]
    uncached = [it["ip"].split(":")[0] for it in passed if it["ip"].split(":")[0] not in cache]
    if uncached:
        print(f"🌍 查询 {len(uncached)} 个新 IP 地理位置（限速 {GEO_MIN_INTERVAL}s/次）...", flush=True)
        for i, ip_str in enumerate(uncached, 1):
            ip_only, country, org = query_ip_info(ip_str, cache, lock, last_req)
            print(f"  [{i}/{len(uncached)}] {ip_only} → {country} / {org}", flush=True)
        save_geo_cache(cache)
    groups = defaultdict(list)
    for it in passed:
        ip_only = it["ip"].split(":")[0]
        info = cache.get(ip_only, {"country": "未知", "org": "未知"})
        groups[info["country"]].append({"addr": it["addr"], "org": info["org"], "avg_ms": it["avg_ms"]})
    return groups

# ================== 输出 ==================

def save_output(passed):
    groups = geo_enrich(passed)
    lines = []
    total = 0
    for country, items in sorted(groups.items()):
        items.sort(key=lambda x: x["avg_ms"])
        lines.append(f"#{country}")
        for idx, it in enumerate(items, 1):
            org_part = it["org"] if it["org"] and it["org"] != "未知" else ""
            label = f"{country}-{idx:03d}"
            if org_part:
                label += f"-{org_part}"
            lines.append(f"{it['addr']}#{label}")
            total += 1
        lines.append("")
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print(f"✅ 通过 {total} 个节点 → {OUTPUT_FILE}", flush=True)

# ================== 主程序 ==================

def main():
    print("🚀 严格模式：强制 200 + cf-ray，速度下限 {} KB/s".format(MIN_SPEED_KBPS), flush=True)
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
