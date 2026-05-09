#!/usr/bin/env python3
"""
Cloudflare ProxyIP 筛选 - 宽容版（接受任何非5xx+cf-ray）
- TCP 连通性
- TLS 握手（SNI 可配置）
- HTTP/HTTPS 测试：只要求包含 cf-ray 头，状态码不限（除 5xx）
- 下载测速（淘汰慢节点）
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

TEST_HOST = "cloudflare.snippets1.dpdns.org"
TEST_PATH = "/?ed=2560"
# 可选：期望响应体包含的关键词（留空则不检查）
EXPECTED_BODY = ""

# SNI 域名（你的代理伪装域名，留空则使用 TEST_HOST）
SNI_DOMAIN = ""

# 支持 TLS 的端口
TLS_PORTS = [443, 8443, 2053, 2083, 2096]
HTTP_PORTS = [80, 8080, 8880, 2052, 2082, 2086, 2095]
DEFAULT_PORTS = TLS_PORTS + HTTP_PORTS

# 测速配置
SPEED_HOST = "speed.cloudflare.com"
SPEED_PATH = "/__down?bytes=102400"
MIN_SPEED_KBPS = 50          # 可根据需要调低或调高
SPEED_TIMEOUT  = 10

LATENCY_ROUNDS  = 1
CONNECT_TIMEOUT = 5
REQ_TIMEOUT     = 6
MAX_WORKERS     = 30

GEO_MIN_INTERVAL = 1.5

# ================== 工具函数 ==================

def parse_ip_port(addr):
    addr = addr.strip()
    if addr.startswith("["):
        end = addr.index("]")
        ip = addr[1:end]
        rest = addr[end+1:]
        if rest.startswith(":"):
            port = int(rest[1:])
            return [(ip, port)]
        else:
            return [(ip, p) for p in DEFAULT_PORTS]
    if ":" in addr:
        parts = addr.rsplit(":", 1)
        try:
            port = int(parts[1])
            return [(parts[0], port)]
        except:
            pass
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
    if port not in TLS_PORTS:
        return False, 0, b''
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        start = time.perf_counter()
        sock = socket.create_connection((ip, port), timeout=CONNECT_TIMEOUT)
        ssock = context.wrap_socket(sock, server_hostname=sni)
        latency = (time.perf_counter() - start) * 1000
        if send_data:
            ssock.sendall(send_data)
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
    if not EXPECTED_BODY:
        return True
    try:
        body = body_bytes.decode(errors="ignore").lower()
        return EXPECTED_BODY.lower() in body
    except:
        return False

def http_connectivity_measure(ip, port):
    """
    通过 ProxyIP 发起 HTTP/HTTPS 请求到 TEST_HOST。
    成功条件：响应头中包含 cf-ray，且状态码不是 5xx。
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
            resp = b""
            header_done = False
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                resp += chunk
                if not header_done and b"\r\n\r\n" in resp:
                    header_done = True
                if header_done and len(resp) > 8192:
                    break
            elapsed = (time.perf_counter() - t0) * 1000
            if not resp:
                return (False, 9999, "空响应")
            line = resp.split(b"\r\n")[0]
            parts = line.decode(errors="ignore").split()
            if len(parts) < 2:
                return (False, 9999, f"异常状态行: {line[:40]}")
            code = int(parts[1])
            # 核心：必须包含 cf-ray 头
            if not has_cf_ray(resp):
                return (False, 9999, f"{code} 无 cf-ray 头")
            # 5xx 视为服务器错误，不可用
            if 500 <= code <= 599:
                return (False, 9999, f"{code} 服务器错误")
            # 检查响应体（可选）
            header_end = resp.find(b"\r\n\r\n")
            body = resp[header_end+4:] if header_end != -1 else b""
            if not response_contains_expected(body):
                return (False, 9999, "响应体不含预期特征")
            return (True, round(elapsed, 1), f"{'TLS' if use_tls else 'HTTP'} {code}+cf-ray")
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

def download_speed_test(ip, port):
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
            print(f"  ✗ {addr}:{port} TCP 不通", flush=True)
            continue

        sni = SNI_DOMAIN if SNI_DOMAIN else TEST_HOST
        if port in TLS_PORTS:
            tls_ok, _, _ = tls_handshake_and_send(ip, port, sni)
            if not tls_ok:
                print(f"  ✗ {addr}:{port} TLS 握手失败 (SNI={sni})", flush=True)
                continue

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

            speed_kbps, _ = download_speed_test(ip, port)
            if speed_kbps < MIN_SPEED_KBPS:
                print(f"  ✗ {addr}:{port} 速度不达标 ({speed_kbps:.0f} KB/s < {MIN_SPEED_KBPS})", flush=True)
                continue

            print(f"  ✓ {addr}:{port} 通过 延迟={avg_lat:.0f}ms 速度={speed_kbps:.0f}KB/s", flush=True)
            r = {
                "addr": f"{ip}:{port}",
                "ip": ip,
                "port": port,
                "avg_ms": round(avg_lat, 1),
                "speed_kbps": speed_kbps,
                "region": region
            }
            if best is None or speed_kbps > best["speed_kbps"]:
                best = r
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

# ================== 地理位置映射（完整版，包含缓存） ==================

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
}

ORG_MAP = {
    "oracle": "甲骨文云", "amazon": "亚马逊云", "google": "谷歌云",
    "microsoft": "Azure", "cloudflare": "Cloudflare", "alibaba": "阿里云",
    "tencent": "腾讯云", "huawei": "华为云", "digitalocean": "机房",
    "vultr": "机房", "ovh": "机房", "hetzner": "机房",
    "private customer": "家宽", "private": "家宽", "customer": "家宽",
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
        print(f"🌍 查询 {len(uncached)} 个新 IP 地理位置...", flush=True)
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
    print("🚀 宽容模式：接受任何非5xx且有cf-ray头的响应", flush=True)
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
