
#!/usr/bin/env python3
"""
Cloudflare ProxyIP 筛选 - 全自动版（筛选+映射）
- HTTP 连通性 + WebSocket 验证
- 状态码白名单，延迟不考核
- 自动通过多个 IP 接口查询地理位置（带限速，防封）
- 输出带国家/运营商标签的节点列表

改进说明：
1. 增加 HTTP 下载数据量测试：在 HTTP 连通性测试中，尝试下载一定量的数据，以模拟真实使用场景下的数据传输能力。
2. 增加延迟测试轮次：将 LATENCY_ROUNDS 增加到 3，以获取更稳定的延迟平均值，并引入抖动（Jitter）评估，淘汰不稳定的 IP。
3. 调整超时时间：适当延长 REQ_TIMEOUT 和 CONNECT_TIMEOUT，以适应更长的下载测试。
4. 修复了 f-string 中不能包含反斜杠的语法错误。
5. 统一测试目标：所有 HTTP 和 WebSocket 测试都将使用 `TEST_HOST`，确保 IP 对您的实际代理域名有效。
6. 强化 TLS 模拟：在 TLS 握手中加入 ALPN（如 `h2`, `http/1.1`），使其更接近真实客户端的指纹。
7. SNI 一致性检查：明确设置 `server_hostname`，确保 SNI 正确发送。
8. 放宽状态码限制：将 `400` 加入允许的状态码白名单，并根据状态码智能调整下载测试逻辑，以兼容反代 IP。
9. **深度优化 WebSocket 握手逻辑**：
    *   使用更通用的浏览器 `User-Agent`。
    *   在 WebSocket 握手失败时，提供更详细的 HTTP 状态码和响应信息，以便诊断问题。
    *   **移除 `Sec-WebSocket-Protocol` 头部中的 `TEST_UUID`**，以进行更通用的 WebSocket 握手测试，避免因特定协议要求而失败。
    *   确保 WebSocket 测试也应用了 ALPN 和 SNI 优化。
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

TEST_HOST = "cloudflare.snippets1.dpdns.org" # 请确保这是您的实际代理域名
TEST_PATH = "/?ed=2560"
TEST_UUID = "362cbd17-f2d0-4b37-8d2c-10a2a45ddefc"

# 增加下载数据量测试的 URL 和预期大小
# 注意：这里将下载测试的 host 也统一到 TEST_HOST，path 也统一到 TEST_PATH
DOWNLOAD_TEST_PATH = TEST_PATH # 使用 TEST_PATH 作为下载测试的路径
EXPECTED_DOWNLOAD_BYTES = 1000000 # 预期下载 1MB

MAX_AVG_LATENCY = 9000
MAX_JITTER      = 9000
LATENCY_ROUNDS  = 3 # 增加延迟测试轮次

CONNECT_TIMEOUT = 8 # 适当延长连接超时
REQ_TIMEOUT     = 15 # 适当延长请求超时，以适应下载测试
MAX_WORKERS     = 30

DEFAULT_PORTS   = [443, 80]
ALLOWED_CODES   = {101, 200, 301, 302, 403, 400} # 允许 400 状态码

# 接口限速（秒）
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

def check_cf_headers(response_bytes):
    try:
        headers = response_bytes.split(b"\r\n\r\n")[0].lower()
    except:
        return False
    return b"cf-ray" in headers or b"server: cloudflare" in headers

def http_connectivity_measure(ip, port):
    family = socket.AF_INET6 if ":" in ip else socket.AF_INET
    
    # 统一使用 TEST_HOST 和 DOWNLOAD_TEST_PATH
    req = (
        f"GET {DOWNLOAD_TEST_PATH} HTTP/1.1\r\n"
        f"Host: {TEST_HOST}\r\n"
        f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36\r\n"
        f"Connection: close\r\n\r\n"
    ).encode()

    def _try(use_tls):
        s = socket.socket(family, socket.SOCK_STREAM)
        t0 = time.perf_counter()
        downloaded_bytes = 0
        try:
            s.settimeout(REQ_TIMEOUT)
            if use_tls:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                # 强化 TLS 模拟：加入 ALPN，并明确设置 server_hostname
                ctx.set_alpn_protocols(["h2", "http/1.1"])
                s = ctx.wrap_socket(s, server_hostname=TEST_HOST)
            s.connect((ip, port))
            s.sendall(req)
            
            # 读取响应头
            resp_headers = b""
            while b"\r\n\r\n" not in resp_headers:
                chunk = s.recv(1024)
                if not chunk:
                    break
                resp_headers += chunk
            
            if not resp_headers:
                return (False, 9999, "空响应")

            line = resp_headers.split(b"\r\n")[0]
            parts = line.decode(errors="ignore").split()
            if len(parts) < 2:
                return (False, 9999, f"异常状态行: {line[:40]}")
            code = int(parts[1])
            
            # 检查状态码是否在允许范围内
            if code not in ALLOWED_CODES:
                return (False, 9999, f"状态码 {code} 未到达 Worker")
            
            # 对于 403 和 400 状态码，检查是否包含 Cloudflare 特征头
            if (code == 403 or code == 400) and not check_cf_headers(resp_headers):
                return (False, 9999, f"{code} 无 CF 头 (可能反代自身或非 CF IP)")
            
            # 只有当状态码为 200 时才进行下载量校验
            if code == 200:
                # 继续读取响应体，模拟下载数据
                while True:
                    chunk = s.recv(4096) # 每次接收 4KB
                    if not chunk:
                        break
                    downloaded_bytes += len(chunk)
                    # 如果下载量达到预期，提前结束
                    if downloaded_bytes >= EXPECTED_DOWNLOAD_BYTES:
                        break

                # 检查下载量是否足够
                if downloaded_bytes < EXPECTED_DOWNLOAD_BYTES * 0.9: # 允许少量误差
                    return (False, 9999, f"下载数据量不足 ({downloaded_bytes}B)")
            else:
                # 对于 400/403 等状态码，只要有 CF 头，就认为 HTTP 连通性通过，不强制下载量
                pass

            elapsed = (time.perf_counter() - t0) * 1000
            
            tls_label = "TLS" if use_tls else "HTTP"
            return (True, round(elapsed, 1), f"{tls_label} {code} ({downloaded_bytes}B)")
        except Exception as e:
            return (False, 9999, str(e)[:50])
        finally:
            s.close()

    ok, lat, detail = _try(True)
    if ok:
        return ok, lat, detail
    ok, lat, detail = _try(False)
    if ok:
        return ok, lat, detail
    return False, 9999, detail

def test_websocket(ip, port, timeout=5):
    family = socket.AF_INET6 if ":" in ip else socket.AF_INET
    # 使用更通用的 User-Agent
    user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
    
    # 第一次尝试：不带 Sec-WebSocket-Protocol 头部中的 TEST_UUID，进行更通用的握手
    req_generic = (
        f"GET {TEST_PATH} HTTP/1.1\r\n"
        f"Host: {TEST_HOST}\r\n"
        f"Upgrade: websocket\r\n"
        f"Connection: Upgrade\r\n"
        f"User-Agent: {user_agent}\r\n"
        f"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
        f"Sec-WebSocket-Version: 13\r\n"
        f"\r\n"
    ).encode()

    # 第二次尝试：带 Sec-WebSocket-Protocol 头部中的 TEST_UUID
    req_uuid = (
        f"GET {TEST_PATH} HTTP/1.1\r\n"
        f"Host: {TEST_HOST}\r\n"
        f"Upgrade: websocket\r\n"
        f"Connection: Upgrade\r\n"
        f"User-Agent: {user_agent}\r\n"
        f"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
        f"Sec-WebSocket-Version: 13\r\n"
        f"Sec-WebSocket-Protocol: {TEST_UUID}\r\n\r\n"
    ).encode()

    def _try_ws(use_tls, request_bytes):
        s = socket.socket(family, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            if use_tls:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                ctx.set_alpn_protocols(["h2", "http/1.1"])
                s = ctx.wrap_socket(s, server_hostname=TEST_HOST)
            s.connect((ip, port))
            s.sendall(request_bytes)
            resp = b""
            while b"\r\n\r\n" not in resp:
                chunk = s.recv(1024)
                if not chunk:
                    break
                resp += chunk
            s.close()
            if not resp:
                return False, "空响应"
            
            line = resp.split(b"\r\n")[0].decode(errors="ignore")
            if line.startswith("HTTP/1.1 101"):
                return True, "WebSocket 握手成功"
            else:
                parts = line.split()
                status_code = int(parts[1]) if len(parts) > 1 else "未知"
                return False, f"WebSocket 握手失败，状态码: {status_code} ({line[:50]})"
        except Exception as e:
            return False, str(e)[:50]

    # 尝试通用 WebSocket 握手 (TLS)
    ok_tls_generic, detail_tls_generic = _try_ws(True, req_generic)
    if ok_tls_generic:
        return True
    
    # 尝试带 UUID 的 WebSocket 握手 (TLS)
    ok_tls_uuid, detail_tls_uuid = _try_ws(True, req_uuid)
    if ok_tls_uuid:
        return True

    # 尝试通用 WebSocket 握手 (HTTP)
    ok_http_generic, detail_http_generic = _try_ws(False, req_generic)
    if ok_http_generic:
        return True

    # 尝试带 UUID 的 WebSocket 握手 (HTTP)
    ok_http_uuid, detail_http_uuid = _try_ws(False, req_uuid)
    if ok_http_uuid:
        return True
    
    # 如果所有尝试都失败，打印详细信息
    print(f"    WebSocket TLS (通用) 失败: {detail_tls_generic}", flush=True)
    print(f"    WebSocket TLS (UUID) 失败: {detail_tls_uuid}", flush=True)
    print(f"    WebSocket HTTP (通用) 失败: {detail_http_generic}", flush=True)
    print(f"    WebSocket HTTP (UUID) 失败: {detail_http_uuid}", flush=True)
    return False

# ================== 单节点筛选 ==================

def filter_one(addr, region):
    print(f"▸ {addr} 开始…", flush=True)
    candidates = parse_ip_port(addr)
    best = None

    for ip, port in candidates:
        if not tcp_ok(ip, port):
            print(f"  ✗ {addr} TCP 不通", flush=True)
            continue

        samples = []
        for rnd in range(LATENCY_ROUNDS):
            ok, lat, info = http_connectivity_measure(ip, port)
            if ok:
                samples.append(lat)
            else:
                print(f"  ✗ {addr} 第{rnd+1}轮 HTTP 失败: {info}", flush=True)
                break
            time.sleep(0.05)
        else:
            avg = statistics.mean(samples)
            # 计算抖动 (Jitter)
            if len(samples) > 1:
                jitter = statistics.stdev(samples)
            else:
                jitter = 0

            if avg > MAX_AVG_LATENCY or jitter > MAX_JITTER:
                print(f"  ✗ {addr} 延迟或抖动过高 (avg={avg:.0f}ms, jitter={jitter:.0f}ms)", flush=True)
                continue

            if not test_websocket(ip, port):
                print(f"  ✗ {addr} HTTP 通过但 WebSocket 失败", flush=True)
                continue

            print(f"  ✓ {addr} HTTP+WS 通过 avg={avg:.0f}ms, jitter={jitter:.0f}ms", flush=True)
            r = {"addr": addr, "ip": ip, "port": port, "avg_ms": round(avg, 1), "jitter_ms": round(jitter, 1), "region": region}
            if best is None or avg < best["avg_ms"]:
                best = r
            continue
        continue

    if best:
        return {"pass": True, **best}
    else:
        print(f"  ✗ {addr} 所有端口不可用", flush=True)
        return {"pass": False, "addr": addr, "region": region}

# ================== CSV 读取（去重） ==================

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
        if str(row.get("success","")).upper() != "TRUE":
            continue
        ip = row.get("input","").strip()
        if not ip or ip in seen:
            continue
        seen.add(ip)
        loc = row.get("location","").strip()
        region = loc.split("(")[0].strip() if loc else "未知"
        proxies.append((ip, region))
    print(f"📊 候选 {len(proxies)} 个（已去重）", flush=True)
    return proxies

# ================== 地理位置映射 ==================

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
    "AF": "阿富汗", "AL": "阿尔及利亚", "DZ": "阿尔及利亚", "AD": "安道尔",
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
    "cloudflare": "Cloudflare", "alibaba": "阿里云",
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
    for k,v in ORG_MAP.items():
        if k in org.lower(): return v
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

# 使用 threading.Lock 来保护 last_req 的并发访问
geo_lock = threading.Lock()
last_geo_req_time = [0.0] # 使用列表包装，以便在函数内部修改

def query_ip_info(ip_str, cache):
    ip_only = ip_str.split(":")[0]
    with geo_lock:
        if ip_only in cache:
            return ip_only, cache[ip_only]["country"], cache[ip_only]["org"]
        now = time.time()
        wait = last_geo_req_time[0] + GEO_MIN_INTERVAL - now
        if wait > 0:
            time.sleep(wait)
        last_geo_req_time[0] = time.time()

    country, org = "未知", "未知"
    
    # 策略 1: ipwho.is (无 Key, 1次/秒)
    data = fetch_json(f"https://ipwho.is/{ip_only}")
    if data and data.get("success"):
        cc = data.get("country_code", "")
        country = COUNTRY_MAP.get(cc, data.get("country", cc or "未知"))
        org = org_cn(data.get("connection", {}).get("isp", ""))
    
    # 策略 2: freeipapi.com (备用)
    if country == "未知":
        data = fetch_json(f"https://freeipapi.com/api/json/{ip_only}")
        if data:
            cc = data.get("countryCode", "")
            country = COUNTRY_MAP.get(cc, data.get("countryName", cc or "未知"))
            org = org_cn(data.get("asnOrganization", ""))

    # 策略 3: ip-api.com (原方案备用)
    if country == "未知":
        data = fetch_json(f"http://ip-api.com/json/{ip_only}?fields=status,countryCode,isp")
        if data and data.get("status") == "success":
            cc = data.get("countryCode", "")
            country = COUNTRY_MAP.get(cc, cc or "未知")
            org = org_cn(data.get("isp", ""))

    with geo_lock:
        cache[ip_only] = {"country": country, "org": org}
    return ip_only, country, org

def geo_enrich(passed):
    cache = load_geo_cache()
    
    uncached = []
    for it in passed:
        ip_only = it["ip"].split(":")[0]
        if ip_only not in cache:
            uncached.append(it["ip"])

    total_uncached = len(uncached)
    if total_uncached > 0:
        print(f"🌍 开始查询 {total_uncached} 个新 IP 的地理位置（限速 {GEO_MIN_INTERVAL}s/次）...", flush=True)
        # 使用线程池并行查询地理位置，但要确保限速逻辑在锁的保护下执行
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = {executor.submit(query_ip_info, ip_str, cache): ip_str for ip_str in uncached}
            for i, future in enumerate(as_completed(futures), 1):
                ip_only, country, org = future.result()
                print(f"  🌍 [{i}/{total_uncached}] {ip_only} → {country} / {org}", flush=True)
        save_geo_cache(cache)

    groups = defaultdict(list)
    for it in passed:
        ip_only = it["ip"].split(":")[0]
        info = cache.get(ip_only, {"country": "未知", "org": "未知"})
        country = info.get("country", "未知")
        org = info.get("org", "未知")
        groups[country].append({
            "addr": it["addr"],
            "org": org,
            "avg_ms": it["avg_ms"],
            "jitter_ms": it["jitter_ms"], # 添加抖动信息
        })

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
            if org_part:
                label = f"{country}-{idx:03d}-{org_part}"
            else:
                label = f"{country}-{idx:03d}"
            # 修复 f-string 语法错误：避免在大括号内使用反斜杠
            addr = it["addr"]
            avg_ms = it["avg_ms"]
            jitter_ms = it["jitter_ms"]
            lines.append(f"{addr}#{label} (avg={avg_ms:.0f}ms, jitter={jitter_ms:.0f}ms)") 
            total += 1
        lines.append("")

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print(f"✅ 通过 {total} 个节点 → {OUTPUT_FILE}", flush=True)

# ================== 主程序 ==================

def main():
    print(f"🚀 全自动筛选+映射：{TEST_HOST}{TEST_PATH}", flush=True)
    print(f"   白名单状态码: {sorted(ALLOWED_CODES)}，403/400 需 CF 头，延迟不考核", flush=True)
    print(f"   HTTP 下载测试 URL: https://{TEST_HOST}{DOWNLOAD_TEST_PATH} (预期 {EXPECTED_DOWNLOAD_BYTES / 1000000:.1f}MB)", flush=True)
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
