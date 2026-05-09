#!/usr/bin/env python3
"""
Cloudflare ProxyIP 筛选 - 增强版（筛选+映射+通用性验证）
- HTTP 连通性 + WebSocket 验证
- 多域名真实访问测试 (www.google.com, www.youtube.com, raw.githubusercontent.com)
- HTTP CONNECT 隧道测试（模拟代理）
- 真实带宽测速（仅运行时显示，不写入输出）
- 状态码白名单，延迟不考核
- 自动通过多个 IP 接口查询地理位置（带限速）
- 输出带国家/运营商标签的节点列表（仅通用节点）
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

# 主验证 Host（原有 Worker）
TEST_HOST = "cloudflare.snippets1.dpdns.org"
TEST_PATH = "/?ed=2560"
TEST_UUID = "362cbd17-f2d0-4b37-8d2c-10a2a45ddefc"

# 下载测速 URL（原有）
DOWNLOAD_TEST_URL = "https://speed.cloudflare.com/__down?bytes=1000000"
EXPECTED_DOWNLOAD_BYTES = 1000000

# 通用性测试 - 多域名（真实外网）
GENERIC_TEST_HOSTS = [
    ("www.google.com", "/generate_204"),          # 返回 204 即可
    ("www.youtube.com", "/"),
    ("raw.githubusercontent.com", "/"),
]
GENERIC_TEST_TIMEOUT = 10

# HTTP CONNECT 隧道测试（模拟代理）
CONNECT_TEST_HOST = "www.google.com"
CONNECT_TEST_PORT = 443

# 带宽测速配置（仅运行时显示）
SPEED_TEST_HOST    = "speed.cloudflare.com"
SPEED_TEST_SIZES   = [
    ("10MB",  10_000_000),
    ("5MB",    5_000_000),
    ("1MB",    1_000_000),
]
SPEED_TEST_TIMEOUT = 20

MAX_AVG_LATENCY = 9000
MAX_JITTER      = 9000
LATENCY_ROUNDS  = 3

CONNECT_TIMEOUT = 8
REQ_TIMEOUT     = 15
MAX_WORKERS     = 30

DEFAULT_PORTS   = [443, 80]
ALLOWED_CODES   = {101, 200, 301, 302, 403}

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

def http_request(ip, port, host, path="/", use_tls=True, timeout=REQ_TIMEOUT, expected_status=None):
    """
    发送简单 HTTP/HTTPS 请求，返回 (成功bool, 状态码, 详情)
    expected_status 若指定则必须匹配，否则任意 2xx/3xx 视为成功
    """
    family = socket.AF_INET6 if ":" in ip else socket.AF_INET

    req = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: Clash/1.18.0\r\n"
        f"Connection: close\r\n\r\n"
    ).encode()

    s = socket.socket(family, socket.SOCK_STREAM)
    try:
        s.settimeout(timeout)
        if use_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            s = ctx.wrap_socket(s, server_hostname=host)
        s.connect((ip, port))
        s.sendall(req)

        resp = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            resp += chunk
            if b"\r\n\r\n" in resp and len(resp) > 10000:  # 避免无限读取
                break

        s.close()

        if not resp:
            return False, 0, "empty response"

        header_part = resp.split(b"\r\n\r\n")[0]
        status_line = header_part.split(b"\r\n")[0]
        parts = status_line.split()
        if len(parts) < 2:
            return False, 0, f"bad status: {status_line[:30]}"
        code = int(parts[1])

        if expected_status is None:
            ok = (200 <= code < 400)
        else:
            ok = (code == expected_status)

        if ok:
            return True, code, f"HTTP/{use_tls} {code}"
        else:
            return False, code, f"unexpected status {code}"
    except Exception as e:
        return False, 0, str(e)[:50]
    finally:
        s.close()

def http_connectivity_measure(ip, port):
    """原有下载测速（用于延迟判定），返回 (成功, 延迟ms, 详情)"""
    family = socket.AF_INET6 if ":" in ip else socket.AF_INET
    req_path = DOWNLOAD_TEST_URL.split('//', 1)[1].split('/', 1)[1] if '//' in DOWNLOAD_TEST_URL else DOWNLOAD_TEST_URL.split('/', 1)[1]
    req_host = DOWNLOAD_TEST_URL.split('//', 1)[1].split('/', 1)[0] if '//' in DOWNLOAD_TEST_URL else TEST_HOST

    req = (
        f"GET /{req_path} HTTP/1.1\r\n"
        f"Host: {req_host}\r\n"
        f"User-Agent: Clash/1.18.0\r\n"
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
                s = ctx.wrap_socket(s, server_hostname=req_host)
            s.connect((ip, port))
            s.sendall(req)

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
            if code not in ALLOWED_CODES:
                return (False, 9999, f"状态码 {code} 未到达 Worker")
            if code == 403 and not check_cf_headers(resp_headers):
                return (False, 9999, "403 无 CF 头 (可能反代自身)")

            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                downloaded_bytes += len(chunk)
                if downloaded_bytes >= EXPECTED_DOWNLOAD_BYTES:
                    break

            elapsed = (time.perf_counter() - t0) * 1000

            if downloaded_bytes < EXPECTED_DOWNLOAD_BYTES * 0.9:
                return (False, 9999, f"下载数据量不足 ({downloaded_bytes}B)")

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

def test_http_connect(ip, port, target_host=CONNECT_TEST_HOST, target_port=CONNECT_TEST_PORT):
    """
    测试 HTTP CONNECT 隧道能力（标准代理方法）
    发送 CONNECT 请求，预期返回 "200 Connection established"
    """
    family = socket.AF_INET6 if ":" in ip else socket.AF_INET
    s = socket.socket(family, socket.SOCK_STREAM)
    s.settimeout(CONNECT_TIMEOUT)
    try:
        s.connect((ip, port))
        # 发送 CONNECT 请求
        connect_req = f"CONNECT {target_host}:{target_port} HTTP/1.1\r\nHost: {target_host}\r\n\r\n".encode()
        s.sendall(connect_req)
        resp = b""
        while b"\r\n\r\n" not in resp:
            chunk = s.recv(1024)
            if not chunk:
                break
            resp += chunk
        s.close()
        if not resp:
            return False
        # 检查响应状态行
        first_line = resp.split(b"\r\n")[0].decode(errors="ignore")
        return "200" in first_line and "connection established" in first_line.lower()
    except Exception:
        return False

def test_generic_https(ip, port):
    """测试多个真实外网域名能否正常访问（通过节点）"""
    for host, path in GENERIC_TEST_HOSTS:
        # 使用 HTTPS (端口443)
        ok, code, detail = http_request(ip, port, host, path, use_tls=True, timeout=GENERIC_TEST_TIMEOUT)
        if not ok:
            return False, f"generic {host} failed: {detail}"
        # 额外要求谷歌的 generate_204 必须是 204 状态码
        if host == "www.google.com" and path == "/generate_204":
            if code != 204:
                return False, f"google generate_204 got {code}"
    return True, "all generic hosts ok"

def measure_bandwidth(ip, port, addr):
    """带宽测速（仅显示）"""
    family = socket.AF_INET6 if ":" in ip else socket.AF_INET

    for label, size in SPEED_TEST_SIZES:
        path = f"/__down?bytes={size}"
        req = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {SPEED_TEST_HOST}\r\n"
            f"User-Agent: Mozilla/5.0\r\n"
            f"Connection: close\r\n\r\n"
        ).encode()

        s = socket.socket(family, socket.SOCK_STREAM)
        s.settimeout(SPEED_TEST_TIMEOUT)
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            s = ctx.wrap_socket(s, server_hostname=SPEED_TEST_HOST)
            s.connect((ip, port))
            s.sendall(req)

            header_buf = b""
            while b"\r\n\r\n" not in header_buf:
                chunk = s.recv(4096)
                if not chunk:
                    break
                header_buf += chunk

            if not header_buf:
                s.close()
                continue

            status_line = header_buf.split(b"\r\n")[0].decode(errors="ignore")
            code = status_line.split()[1] if len(status_line.split()) >= 2 else "0"
            if code not in ("200", "206"):
                s.close()
                continue

            body_start = header_buf.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in header_buf else b""
            downloaded = len(body_start)
            t0 = time.perf_counter()
            while downloaded < size:
                chunk = s.recv(65536)
                if not chunk:
                    break
                downloaded += len(chunk)
            elapsed = time.perf_counter() - t0
            s.close()

            if downloaded < size * 0.5:
                continue

            speed_mbps = (downloaded * 8) / (elapsed * 1_000_000)
            speed_mbps = round(speed_mbps, 2)

            if speed_mbps < 0.5:
                quality = "⚠️  极差，连 360p 都可能卡"
            elif speed_mbps < 1.5:
                quality = "⚠️  勉强 480p"
            elif speed_mbps < 5.0:
                quality = "✅ 够 720p"
            elif speed_mbps < 20.0:
                quality = "✅ 够 1080p"
            elif speed_mbps < 50.0:
                quality = "🚀 够 4K"
            else:
                quality = "🚀 够 8K"

            print(f"  📶 {addr} 带宽测速({label})：{speed_mbps:.2f} Mbps  {quality}", flush=True)
            return
        except Exception:
            try:
                s.close()
            except:
                pass
            continue

    print(f"  📶 {addr} 带宽测速：❌ 失败（连接超时或节点限速）", flush=True)

# ================== 单节点筛选（增强） ==================

def filter_one(addr, region):
    print(f"▸ {addr} 开始…", flush=True)
    candidates = parse_ip_port(addr)
    best = None

    for ip, port in candidates:
        # 1. TCP 连通性
        if not tcp_ok(ip, port):
            print(f"  ✗ {addr} TCP 不通", flush=True)
            continue

        # 2. 延迟 + 下载验证（原有）
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
            jitter = statistics.stdev(samples) if len(samples) > 1 else 0

            if avg > MAX_AVG_LATENCY or jitter > MAX_JITTER:
                print(f"  ✗ {addr} 延迟或抖动过高 (avg={avg:.0f}ms, jitter={jitter:.0f}ms)", flush=True)
                continue

            # 3. WebSocket 验证
            if not test_websocket(ip, port):
                print(f"  ✗ {addr} HTTP 通过但 WebSocket 失败", flush=True)
                continue

            # 4. 新增：HTTP CONNECT 代理隧道测试
            if not test_http_connect(ip, port):
                print(f"  ✗ {addr} HTTP CONNECT 隧道失败（不支持代理）", flush=True)
                continue

            # 5. 新增：多域名真实 HTTPS 访问测试
            generic_ok, generic_msg = test_generic_https(ip, port)
            if not generic_ok:
                print(f"  ✗ {addr} 通用性测试失败: {generic_msg}", flush=True)
                continue

            # 所有测试通过
            print(f"  ✓ {addr} HTTP+WS+CONNECT+通用域名 全部通过 avg={avg:.0f}ms, jitter={jitter:.0f}ms", flush=True)

            # 带宽测速（仅显示）
            measure_bandwidth(ip, port, addr)

            r = {"addr": addr, "ip": ip, "port": port, "avg_ms": round(avg, 1), "jitter_ms": round(jitter, 1), "region": region}
            if best is None or avg < best["avg_ms"]:
                best = r
            continue
        continue

    if best:
        return {"pass": True, **best}
    else:
        print(f"  ✗ {addr} 所有端口不可用或不满足通用性标准", flush=True)
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

# ================== 地理位置映射（保持不变） ==================

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
    # 可继续补充，但不影响运行
}

ORG_MAP = {
    "oracle": "甲骨文云", "amazon": "亚马逊云", "google": "谷歌云", "microsoft": "Azure",
    "cloudflare": "Cloudflare", "alibaba": "阿里云", "digitalocean": "机房", "vultr": "机房",
    # 缩短版，可添加更多
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

geo_lock = threading.Lock()
last_geo_req_time = [0.0]

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
    if uncached:
        print(f"🌍 开始查询 {len(uncached)} 个新 IP 的地理位置（限速 {GEO_MIN_INTERVAL}s/次）...", flush=True)
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = {executor.submit(query_ip_info, ip_str, cache): ip_str for ip_str in uncached}
            for i, future in enumerate(as_completed(futures), 1):
                ip_only, country, org = future.result()
                print(f"  🌍 [{i}/{len(uncached)}] {ip_only} → {country} / {org}", flush=True)
        save_geo_cache(cache)
    groups = defaultdict(list)
    for it in passed:
        ip_only = it["ip"].split(":")[0]
        info = cache.get(ip_only, {"country": "未知", "org": "未知"})
        groups[info["country"]].append({
            "addr": it["addr"],
            "org": info["org"],
            "avg_ms": it["avg_ms"],
            "jitter_ms": it["jitter_ms"],
        })
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
            label = f"{country}-{idx:03d}-{org_part}" if org_part else f"{country}-{idx:03d}"
            lines.append(f"{it['addr']}#{label} (avg={it['avg_ms']:.0f}ms, jitter={it['jitter_ms']:.0f}ms)")
            total += 1
        lines.append("")
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print(f"✅ 通过通用性验证的节点共 {total} 个 → {OUTPUT_FILE}", flush=True)

# ================== 主程序 ==================

def main():
    print(f"🚀 Cloudflare ProxyIP 筛选增强版", flush=True)
    print(f"   验证项: HTTP下载+WS+HTTP CONNECT+多域名真实访问", flush=True)
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

    print(f"\n📊 总计 {len(proxies)} | ✅ 通用节点 {len(passed)} | ❌ 淘汰 {failed}", flush=True)
    if passed:
        save_output(passed)
    else:
        print("❌ 无节点通过通用性验证", flush=True)

if __name__ == "__main__":
    main()
