#!/usr/bin/env python3
"""
Cloudflare ProxyIP 筛选 - Clash 完全兼容版
- HTTP 连通性（下载测速） + WebSocket 握手 + WebSocket 数据收发测试
- 严格 TLS 证书验证（可选，模拟 Clash 配置）
- 延迟多轮 + 抖动评估
- 自动地理位置查询（带限速，防封）
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
import threading

# ================== 配置 ==================
INPUT_FILE  = "proxyip/results.csv"
OUTPUT_FILE = "proxyip_output.txt"
CACHE_FILE  = "ip_cache.json"

TEST_HOST = "cloudflare.snippets1.dpdns.org"
TEST_PATH = "/?ed=2560"
TEST_UUID = "362cbd17-f2d0-4b37-8d2c-10a2a45ddefc"

DOWNLOAD_TEST_URL = "https://speed.cloudflare.com/__down?bytes=1000000"
EXPECTED_DOWNLOAD_BYTES = 1000000

MAX_AVG_LATENCY = 9000
MAX_JITTER      = 9000
LATENCY_ROUNDS  = 3

CONNECT_TIMEOUT = 8
REQ_TIMEOUT     = 15
MAX_WORKERS     = 30

DEFAULT_PORTS   = [443, 80]
ALLOWED_CODES   = {101, 200, 301, 302, 403}

GEO_MIN_INTERVAL = 1.5

# ---------- 新增：模拟 Clash 行为 ----------
# 如果您的 Clash 配置中 skip-cert-verify: false，请设置为 True
# 如果您的 Clash 中跳过了证书校验（skip-cert-verify: true），请保持 False
STRICT_TLS_VERIFY = True   # 改为 True 会淘汰证书不匹配的节点

# WebSocket 数据测试配置
WS_PING_MESSAGE = "ping"
WS_PONG_MESSAGE = "pong"
WS_TEST_TIMEOUT = 5

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
                if STRICT_TLS_VERIFY:
                    ctx.check_hostname = True
                    ctx.verify_mode = ssl.CERT_REQUIRED
                else:
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
        except ssl.SSLCertVerificationError as e:
            return (False, 9999, f"TLS证书校验失败: {e}")
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

# ---------- WebSocket 帧操作（用于数据测试）----------
def send_websocket_frame(sock, payload, opcode=0x81):
    """发送带掩码的 WebSocket 文本帧"""
    length = len(payload)
    frame = bytearray()
    frame.append(opcode)
    mask_bit = 0x80
    if length <= 125:
        frame.append(mask_bit | length)
    elif length <= 65535:
        frame.append(mask_bit | 126)
        frame.extend(length.to_bytes(2, byteorder='big'))
    else:
        frame.append(mask_bit | 127)
        frame.extend(length.to_bytes(8, byteorder='big'))
    mask = bytes([0x12, 0x34, 0x56, 0x78])  # 固定掩码，测试足够
    frame.extend(mask)
    masked_payload = bytearray(payload, 'utf-8')
    for i in range(len(masked_payload)):
        masked_payload[i] ^= mask[i % 4]
    frame.extend(masked_payload)
    sock.sendall(frame)

def recv_websocket_frame(sock, timeout):
    """接收 WebSocket 帧，返回 payload 字符串"""
    sock.settimeout(timeout)
    try:
        header = sock.recv(2)
        if len(header) < 2:
            return None
        byte1, byte2 = header[0], header[1]
        opcode = byte1 & 0x0F
        masked = (byte2 & 0x80) != 0
        payload_len = byte2 & 0x7F
        if payload_len == 126:
            ext_len = sock.recv(2)
            payload_len = int.from_bytes(ext_len, byteorder='big')
        elif payload_len == 127:
            ext_len = sock.recv(8)
            payload_len = int.from_bytes(ext_len, byteorder='big')
        mask = None
        if masked:
            mask = sock.recv(4)
        data = sock.recv(payload_len)
        if mask:
            data = bytes(data[i] ^ mask[i % 4] for i in range(len(data)))
        if opcode == 0x01:  # 文本帧
            return data.decode('utf-8', errors='ignore')
        return None
    except Exception:
        return None

def test_websocket_data(ip, port):
    """
    完整 WebSocket 测试：握手 + 发送 ping 并等待 pong
    返回 (成功, 详细信息)
    """
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

    sock = None
    try:
        ctx = ssl.create_default_context()
        if STRICT_TLS_VERIFY:
            ctx.check_hostname = True
            ctx.verify_mode = ssl.CERT_REQUIRED
        else:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        sock = ctx.wrap_socket(socket.socket(family, socket.SOCK_STREAM), server_hostname=TEST_HOST)
        sock.settimeout(WS_TEST_TIMEOUT)
        sock.connect((ip, port))
        sock.sendall(req)

        # 读取握手响应
        resp = b""
        while b"\r\n\r\n" not in resp:
            chunk = sock.recv(1024)
            if not chunk:
                break
            resp += chunk
        if not resp:
            return False, "WebSocket 握手无响应"
        line = resp.split(b"\r\n")[0].decode(errors="ignore")
        if not line.startswith("HTTP/1.1 101"):
            return False, f"WebSocket 握手失败: {line}"

        # 发送 ping 并等待 pong
        send_websocket_frame(sock, WS_PING_MESSAGE)
        pong = recv_websocket_frame(sock, WS_TEST_TIMEOUT)
        if pong is None:
            return False, "WebSocket 数据接收超时"
        if WS_PONG_MESSAGE not in pong:
            return False, f"收到非预期响应: {pong}"
        return True, "WebSocket 数据通道正常"
    except ssl.SSLCertVerificationError as e:
        return False, f"TLS证书校验失败: {e}"
    except Exception as e:
        return False, str(e)[:50]
    finally:
        if sock:
            sock.close()

# ================== 单节点筛选（增强） ==================

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
            jitter = statistics.stdev(samples) if len(samples) > 1 else 0

            if avg > MAX_AVG_LATENCY or jitter > MAX_JITTER:
                print(f"  ✗ {addr} 延迟或抖动过高 (avg={avg:.0f}ms, jitter={jitter:.0f}ms)", flush=True)
                continue

            # WebSocket 数据测试（含握手 + 数据收发）
            ws_ok, ws_msg = test_websocket_data(ip, port)
            if not ws_ok:
                print(f"  ✗ {addr} WebSocket 数据测试失败: {ws_msg}", flush=True)
                continue

            print(f"  ✓ {addr} HTTP+WS数据 全部通过 avg={avg:.0f}ms, jitter={jitter:.0f}ms", flush=True)

            r = {"addr": addr, "ip": ip, "port": port, "avg_ms": round(avg, 1), "jitter_ms": round(jitter, 1), "region": region}
            if best is None or avg < best["avg_ms"]:
                best = r
            continue
        continue

    if best:
        return {"pass": True, **best}
    else:
        print(f"  ✗ {addr} 所有端口不可用或不满足 Clash 兼容性", flush=True)
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
    # 此处省略部分国家，您原有代码中已完整，可自行补充
}
ORG_MAP = {
    "oracle": "甲骨文云", "amazon": "亚马逊云", "google": "谷歌云", "microsoft": "Azure",
    "cloudflare": "Cloudflare", "alibaba": "阿里云", "digitalocean": "机房", "vultr": "机房",
    "sk broadband": "SK宽带", "korea telecom": "韩国电信", "kt corp": "韩国电信",
    "hkt": "香港电讯", "hkbn": "香港宽频", "private customer": "家宽", "private": "家宽",
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
    print(f"✅ 通过 {total} 个节点 → {OUTPUT_FILE}", flush=True)

# ================== 主程序 ==================

def main():
    print(f"🚀 Clash 完全兼容模式：{TEST_HOST}{TEST_PATH}", flush=True)
    print(f"   严格证书验证: {'开启' if STRICT_TLS_VERIFY else '关闭'}", flush=True)
    print(f"   WebSocket 数据测试: ping -> pong", flush=True)
    proxies = read_csv()
    if not proxies:
        print("❌ 没有候选 IP，请检查 INPUT_FILE 路径和 CSV 格式", flush=True)
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
