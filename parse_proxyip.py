#!/usr/bin/env python3
"""
Cloudflare ProxyIP 筛选 - 全自动版（筛选+映射）
- HTTP 连通性 + WebSocket 验证
- 状态码白名单，延迟不考核
- 自动通过多个 IP 接口查询地理位置（带限速，防封）
- 输出带国家/运营商标签的节点列表
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

# ================== 配置 ==================
INPUT_FILE  = "proxyip/results.csv"
OUTPUT_FILE = "proxyip_output.txt"
CACHE_FILE  = "ip_cache.json"

TEST_HOST = "cloudflare.snippets1.dpdns.org"
TEST_PATH = "/?ed=2560"
TEST_UUID = "362cbd17-f2d0-4b37-8d2c-10a2a45ddefc"

MAX_AVG_LATENCY = 9000
MAX_JITTER      = 9000
LATENCY_ROUNDS  = 1

CONNECT_TIMEOUT = 5
REQ_TIMEOUT     = 6
MAX_WORKERS     = 30

DEFAULT_PORTS   = [443, 80]
ALLOWED_CODES   = {101, 200, 301, 302, 403}

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
            resp = b""
            while b"\r\n\r\n" not in resp:
                chunk = s.recv(1024)
                if not chunk:
                    break
                resp += chunk
            elapsed = (time.perf_counter() - t0) * 1000
            if not resp:
                return (False, 9999, "空响应")
            line = resp.split(b"\r\n")[0]
            parts = line.decode(errors="ignore").split()
            if len(parts) < 2:
                return (False, 9999, f"异常状态行: {line[:40]}")
            code = int(parts[1])
            if code not in ALLOWED_CODES:
                return (False, 9999, f"状态码 {code} 未到达 Worker")
            if code == 403 and not check_cf_headers(resp):
                return (False, 9999, "403 无 CF 头 (可能反代自身)")
            return (True, round(elapsed, 1), f"{'TLS' if use_tls else 'HTTP'} {code}")
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
    req = (
        f"GET {TEST_PATH} HTTP/1.1\r\n"
        f"Host: {TEST_HOST}\r\n"
        f"Upgrade: websocket\r\n"
        f"Connection: Upgrade\r\n"
        f"User-Agent: Clash/1.18.0\r\n"
        f"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
        f"Sec-WebSocket-Version: 13\r\n"
        f"Sec-WebSocket-Protocol: {TEST_UUID}\r\n\r\n"
    ).encode()

    def _try(use_tls):
        s = socket.socket(family, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            if use_tls:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                s = ctx.wrap_socket(s, server_hostname=TEST_HOST)
            s.connect((ip, port))
            s.sendall(req)
            resp = b""
            while b"\r\n\r\n" not in resp:
                chunk = s.recv(1024)
                if not chunk:
                    break
                resp += chunk
            s.close()
            if not resp:
                return False
            line = resp.split(b"\r\n")[0].decode(errors="ignore")
            return line.startswith("HTTP/1.1 101")
        except Exception:
            return False

    return _try(True) or _try(False)

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

            if not test_websocket(ip, port):
                print(f"  ✗ {addr} HTTP 通过但 WebSocket 失败", flush=True)
                continue

            print(f"  ✓ {addr} HTTP+WS 通过 avg={avg:.0f}ms", flush=True)
            r = {"addr": addr, "ip": ip, "port": port, "avg_ms": round(avg, 1), "region": region}
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
    # ========== 云厂商 & 数据中心 ==========
    "oracle": "甲骨文云", "oracle corporation": "甲骨文云", "oracle cloud": "甲骨文云",
    "amazon": "亚马逊云", "amazon.com": "亚马逊云", "aws": "亚马逊云",
    "google": "谷歌云", "google cloud": "谷歌云",
    "microsoft": "Azure", "azure": "Azure",
    "cloudflare": "Cloudflare",
    "alibaba": "阿里云", "aliyun": "阿里云",
    "tencent": "腾讯云", "tencent cloud": "腾讯云",
    "huawei": "华为云",
    "ibm": "IBM云",
    "digitalocean": "DigitalOcean",
    "linode": "Linode",
    "vultr": "Vultr",
    "ovh": "OVH",
    "hetzner": "Hetzner",
    "leaseweb": "Leaseweb",
    "choopa": "Choopa",
    "cogent": "Cogent",
    "zenlayer": "Zenlayer",
    "akamai": "Akamai",
    "fastly": "Fastly",
    "upcloud": "UpCloud",
    "scaleway": "Scaleway",
    "serverius": "Serverius",
    "m247": "M247",
    "fdcservers": "FDC机房",
    "ctgserver": "CTG机房",
    "oneprovider": "OneProvider",
    "oneasiahost": "OneAsiaHost",
    "nexeon": "Nexeon",
    "lamhosting": "LamHosting",
    "ipxo": "IPXO",
    "hostkey": "Hostkey",
    "cgi global": "CGI Global",
    "bytevirt": "ByteVirt",
    "austole": "Austole",
    "veesp": "Veesp",
    "sakura": "樱花云",
    "pittqiao": "PittQiao",
    "fomo crew": "FomoCrew",
    "emagine": "Emagine",
    "dromatics": "Dromatics",
    "digital united": "Digital United",
    "akile": "Akile",
    "akari": "Akari",
    "a.i.p. italia": "AIP Italia",

    # ========== 美国 ISP ==========
    "comcast": "康卡斯特", "comcast cable": "康卡斯特",
    "verizon": "威瑞森", "verizon wireless": "威瑞森",
    "at&t": "AT&T", "att": "AT&T",
    "spectrum": "Spectrum", "charter": "Spectrum",
    "frontier": "Frontier", "frontier communications": "Frontier",
    "centurylink": "世纪互联", "lumen": "Lumen",
    "cox": "Cox",
    "gtt communications": "GTT通信", "gtt.net": "GTT通信",
    "he.net": "Hurricane Electric",
    "t-mobile": "T-Mobile", "tmobile": "T-Mobile",
    "sprint": "Sprint",
    "windstream": "Windstream",
    "suddenlink": "Suddenlink",
    "altafiber": "Altafiber",
    "cincinnati bell": "辛辛那提贝尔",
    "consolidated communications": "Consolidated",
    "crown castle": "Crown Castle",
    "zayo": "Zayo",
    "tw telecom": "TW Telecom",

    # ========== 加拿大 ISP ==========
    "bell canada": "贝尔加拿大",
    "rogers": "罗杰斯",
    "telus": "Telus",
    "shaw": "Shaw",
    "videotron": "Videotron",

    # ========== 英国 / 欧洲 ISP ==========
    "virgin media": "维珍传媒", "virgin media limited": "维珍传媒",
    "british telecom": "英国电信", "bt": "英国电信",
    "sky": "Sky",
    "talktalk": "TalkTalk",
    "plusnet": "Plusnet",
    "ee": "EE",
    "vodafone": "沃达丰",
    "swisscom": "瑞士电信", "swisscom schweiz ag": "瑞士电信",
    "virgin media limited": "维珍传媒", "gtt communications inc.": "GTT 通讯",
    "deutsche telekom": "德国电信",
    "telefonica": "西班牙电信",
    "orange": "Orange",
    "sfr": "SFR",
    "bouygues": "布依格",
    "kpn": "KPN",
    "telenor": "Telenor",
    "telia": "Telia",
    "elisa": "Elisa",
    "proximus": "Proximus",

    # ========== 日本 ISP ==========
    "softbank": "软银", "softbank mobile": "软银", "softbank mobile corp.": "软银",
    "kddi": "KDDI", "au": "KDDI",
    "ntt": "NTT", "ntt communications": "NTT",
    "sony network": "So-net",
    "rakuten mobile": "乐天移动",
    "iij": "IIJ",

    # ========== 韩国 ISP ==========
    "sk telecom": "SK电信", "sk telecom co.": "SK电信",
    "sk broadband": "SK宽带",
    "kt corp": "韩国电信", "korea telecom": "韩国电信",
    "lg uplus": "LG U+",

    # ========== 台湾 ISP ==========
    "chunghwa": "中华电信", "hinet": "中华电信",
    "twm": "台湾大哥大", "taiwan mobile": "台湾大哥大",
    "fareastone": "远传电信",

    # ========== 香港 ISP ==========
    "hkbn": "香港宽频", "hong kong broadband": "香港宽频",
    "hkt": "香港电讯", "pccw": "香港电讯", "csl": "香港电讯",
    "cmhk": "中国移动香港",
    "three hong kong": "和记电讯",

    # ========== 东南亚 ISP ==========
    "tm technology services": "马来西亚电信", "tmnet": "马来西亚电信",
    "tt dotcom": "TT dotcom", "tt dotcom sdn bhd": "TT dotcom",
    "time dotcom": "Time dotcom",
    "maxis": "明讯",
    "celcom": "天地通",
    "digi": "Digi",
    "singtel": "新加坡电信",
    "starhub": "星和",
    "m1": "M1",
    "true": "True", "true internet": "True",
    "ais": "AIS",
    "vnpt": "VNPT",
    "fpt": "FPT",
    "indosat": "Indosat",
    "telkomsel": "Telkomsel",
    "xl axiata": "XL Axiata",
    "globe": "Globe",
    "smart": "Smart",

    # ========== 其他地区 ==========
    "telstra": "澳洲电信",
    "optus": "Optus",
    "spark": "Spark NZ",
    "vodacom": "Vodacom",
    "mtn": "MTN",

    # ========== 家宽 / 企业标识 ==========
    "private customer": "家宽", "private": "家宽", "customer": "家宽",
    "residential": "家宽", "home": "家宽",
    "enterprise": "企宽", "business": "企宽",
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

    with lock:
        cache[ip_only] = {"country": country, "org": org}
    return ip_only, country, org

def geo_enrich(passed):
    cache = load_geo_cache()
    lock = __import__('threading').Lock()
    last_req = [0.0]

    uncached = []
    for it in passed:
        ip_only = it["ip"].split(":")[0]
        if ip_only not in cache:
            uncached.append(it["ip"])

    total_uncached = len(uncached)
    if total_uncached > 0:
        print(f"🌍 开始查询 {total_uncached} 个新 IP 的地理位置（限速 {GEO_MIN_INTERVAL}s/次）...", flush=True)
        for i, ip_str in enumerate(uncached, 1):
            ip_only, country, org = query_ip_info(ip_str, cache, lock, last_req)
            print(f"  🌍 [{i}/{total_uncached}] {ip_only} → {country} / {org}", flush=True)
        save_geo_cache(cache)

    groups = defaultdict(list)
    for it in passed:
        ip_only = it["ip"].split(":")[0]
        info = cache.get(ip_only, {"country": "未知", "org": "未知"})
        country = info.get("country", "未知")
        org_raw = info.get("org", "未知")
        org = org_cn(org_raw)   # ⬅️ 这里加上实时映射
        groups[country].append({
            "addr": it["addr"],
            "org": org,
            "avg_ms": it["avg_ms"],
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
            lines.append(f"{it['addr']}#{label}")
            total += 1
        lines.append("")

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print(f"✅ 通过 {total} 个节点 → {OUTPUT_FILE}", flush=True)

# ================== 主程序 ==================

def main():
    print(f"🚀 全自动筛选+映射：{TEST_HOST}{TEST_PATH}", flush=True)
    print(f"   白名单状态码: {sorted(ALLOWED_CODES)}，403 需 CF 头，延迟不考核", flush=True)
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
