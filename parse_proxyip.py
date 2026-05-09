#!/usr/bin/env python3
"""
Cloudflare ProxyIP 筛选 - 精简准确版（TCP + 真实HTTP验证）
- 直接验证能否通过该IP访问 cloudflare.com 的 /cdn-cgi/trace
- 无WebSocket、无下载测速，避免误判
- 保留延迟测量（可选）
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

# 验证目标：使用 Cloudflare 官方 /cdn-cgi/trace
TEST_URL_HTTP  = "http://cloudflare.com/cdn-cgi/trace"
TEST_URL_HTTPS = "https://cloudflare.com/cdn-cgi/trace"

CONNECT_TIMEOUT = 5
REQ_TIMEOUT     = 6
MAX_WORKERS     = 30
LATENCY_ROUNDS  = 1          # 测1轮延迟即可

DEFAULT_PORTS   = [443, 80]  # 优先尝试443，再80

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

def check_cf_trace(response_text):
    """检查响应是否为 Cloudflare /cdn-cgi/trace 的典型内容"""
    # 典型内容包含 "cf-ray=" 或 "server=cloudflare"
    return "cf-ray=" in response_text or "server=cloudflare" in response_text

def http_proxy_test(ip, port):
    """
    通过 ProxyIP 发起 HTTP/HTTPS 请求到 cloudflare.com/cdn-cgi/trace
    返回 (成功与否, 延迟毫秒, 详细信息)
    """
    family = socket.AF_INET6 if ":" in ip else socket.AF_INET
    # 优先尝试 HTTPS (443), 若失败再尝试 HTTP (80)
    for use_tls, url in [(True, TEST_URL_HTTPS), (False, TEST_URL_HTTP)]:
        # 解析URL得到 host 和 path
        if use_tls:
            req_host = "cloudflare.com"
            req_port = 443
            req_path = "/cdn-cgi/trace"
        else:
            req_host = "cloudflare.com"
            req_port = 80
            req_path = "/cdn-cgi/trace"

        req = (
            f"GET {req_path} HTTP/1.1\r\n"
            f"Host: {req_host}\r\n"
            f"User-Agent: Clash/1.18.0\r\n"
            f"Connection: close\r\n\r\n"
        ).encode()

        s = socket.socket(family, socket.SOCK_STREAM)
        t0 = time.perf_counter()
        try:
            s.settimeout(REQ_TIMEOUT)
            if use_tls:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                s = ctx.wrap_socket(s, server_hostname=req_host)
            s.connect((ip, port))   # 连接到 ProxyIP 的指定端口
            s.sendall(req)

            # 读取响应
            resp = b""
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                resp += chunk
                if b"\r\n\r\n" in resp and len(resp) > 4096:
                    # 已经拿到足够数据（trace 内容很小）
                    break
            elapsed = (time.perf_counter() - t0) * 1000

            if not resp:
                continue
            # 分离 headers 和 body
            header_end = resp.find(b"\r\n\r\n")
            if header_end == -1:
                continue
            body = resp[header_end+4:].decode(errors="ignore")
            # 检查状态码 (取第一行)
            first_line = resp.split(b"\r\n")[0].decode(errors="ignore")
            if "200" not in first_line:
                continue
            if check_cf_trace(body):
                return (True, round(elapsed, 1), f"{'HTTPS' if use_tls else 'HTTP'} 200 + cf-trace")
        except Exception as e:
            pass
        finally:
            s.close()
    return (False, 9999, "无法验证 Cloudflare trace")

# ================== 单节点筛选 ==================

def filter_one(addr, region):
    print(f"▸ {addr} 开始…", flush=True)
    candidates = parse_ip_port(addr)
    best = None

    for ip, port in candidates:
        # 1. TCP 连通性
        if not tcp_ok(ip, port):
            print(f"  ✗ {addr} TCP 不通", flush=True)
            continue

        # 2. 延迟采样（可选，仅用于输出排序）
        latencies = []
        for _ in range(LATENCY_ROUNDS):
            ok, lat, _ = http_proxy_test(ip, port)
            if ok:
                latencies.append(lat)
                # 只测一轮就够，不再 sleep
                break
        if not latencies:
            print(f"  ✗ {addr} 无法通过 HTTP/HTTPS 验证", flush=True)
            continue

        avg_lat = statistics.mean(latencies)

        print(f"  ✓ {addr} 验证通过 延迟={avg_lat:.0f}ms", flush=True)
        r = {
            "addr": addr,
            "ip": ip,
            "port": port,
            "avg_ms": round(avg_lat, 1),
            "region": region
        }
        # 选择延迟最低的端口
        if best is None or avg_lat < best["avg_ms"]:
            best = r

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
# （保持不变，完整复制原来的 COUNTRY_MAP, ORG_MAP, 函数等）
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
            print(f"  🌍 [{i}/{len(uncached)}] {ip_only} → {country} / {org}", flush=True)
        save_geo_cache(cache)

    groups = defaultdict(list)
    for it in passed:
        ip_only = it["ip"].split(":")[0]
        info = cache.get(ip_only, {"country": "未知", "org": "未知"})
        country = info["country"]
        org = info["org"]
        groups[country].append({"addr": it["addr"], "org": org, "avg_ms": it["avg_ms"]})
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
    print("🚀 精简筛选：TCP + Cloudflare /cdn-cgi/trace 真实验证", flush=True)
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
    import threading
    main()
