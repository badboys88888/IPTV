#!/usr/bin/env python3
"""
Cloudflare ProxyIP 筛选 - 最终稳定版
- HTTP 连通性 + 强制 CF 头检查
- WebSocket 握手验证（可选数据验证）
- 不进行速度测试，避免误杀
- 输出只包含国家/运营商标签，无任何测速文字
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

LATENCY_ROUNDS  = 1
CONNECT_TIMEOUT = 5
REQ_TIMEOUT     = 6
MAX_WORKERS     = 30

DEFAULT_PORTS   = [443, 80]
ALLOWED_CODES   = {101, 200, 301, 302, 403}

# 严格模式：强制检查 Cloudflare 头部（强烈建议开启）
STRICT_CF_HEADER = True

# WebSocket 数据验证（开启可杜绝假 WS，但需 Worker 支持回应）
ENABLE_WS_DATA_TEST = False   # 设为 False 只做握手验证，避免 Worker 无响应导致失败

# 速度测试（完全关闭，避免误杀）
ENABLE_SPEED_TEST = False

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

def has_cf_headers(response_bytes):
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
                return (False, 9999, f"状态码 {code}")
            if STRICT_CF_HEADER and not has_cf_headers(resp):
                return (False, 9999, f"{code} 无 CF 头")
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

def build_ws_frame(payload: bytes, opcode=0x81, mask=True) -> bytes:
    length = len(payload)
    header = bytearray()
    header.append(0x80 | opcode)
    if mask:
        if length < 126:
            header.append(0x80 | length)
        elif length < 65536:
            header.append(0x80 | 126)
            header.extend(length.to_bytes(2, 'big'))
        else:
            header.append(0x80 | 127)
            header.extend(length.to_bytes(8, 'big'))
        mask_key = os.urandom(4)
        header.extend(mask_key)
        masked = bytearray(payload[i] ^ mask_key[i % 4] for i in range(length))
        return bytes(header) + masked
    else:
        if length < 126:
            header.append(length)
        elif length < 65536:
            header.append(126)
            header.extend(length.to_bytes(2, 'big'))
        else:
            header.append(127)
            header.extend(length.to_bytes(8, 'big'))
        return bytes(header) + payload

def test_websocket(ip, port, timeout=6):
    """WebSocket 握手验证（可选数据收发）"""
    family = socket.AF_INET6 if ":" in ip else socket.AF_INET
    ws_key = "dGhlIHNhbXBsZSBub25jZQ=="
    req = (
        f"GET {TEST_PATH} HTTP/1.1\r\n"
        f"Host: {TEST_HOST}\r\n"
        f"Upgrade: websocket\r\n"
        f"Connection: Upgrade\r\n"
        f"User-Agent: Clash/1.18.0\r\n"
        f"Sec-WebSocket-Key: {ws_key}\r\n"
        f"Sec-WebSocket-Version: 13\r\n"
        f"Sec-WebSocket-Protocol: {TEST_UUID}\r\n\r\n"
    ).encode()

    def _attempt(use_tls):
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
                    return False
                resp += chunk
            if b"101" not in resp.split(b"\r\n")[0]:
                return False
            if ENABLE_WS_DATA_TEST:
                test_msg = "ping".encode()
                frame = build_ws_frame(test_msg, opcode=0x81, mask=True)
                s.sendall(frame)
                try:
                    s.settimeout(3)
                    data = s.recv(1024)
                    if not data:
                        return False
                except socket.timeout:
                    return False
            return True
        except Exception:
            return False
        finally:
            s.close()
    return _attempt(True) or _attempt(False)

# ================== 单节点筛选（无速度测试） ==================

def filter_one(addr, region):
    print(f"▸ {addr} 开始…", flush=True)
    candidates = parse_ip_port(addr)
    best = None

    for ip, port in candidates:
        if not tcp_ok(ip, port):
            print(f"  ✗ {addr} TCP 不通", flush=True)
            continue

        # HTTP 连通性 + CF 头检查
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
            # WebSocket 验证
            if not test_websocket(ip, port):
                print(f"  ✗ {addr} WebSocket 握手失败", flush=True)
                continue

            print(f"  ✓ {addr} 验证通过 延迟={avg_lat:.0f}ms", flush=True)
            r = {
                "addr": addr, "ip": ip, "port": port,
                "avg_ms": round(avg_lat, 1),
                "region": region
            }
            if best is None or avg_lat < best["avg_ms"]:
                best = r
            # 只要有一个端口成功就停止尝试其他端口
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

# ================== 地理位置映射（保持原样，略作精简） ==================

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

# ================== 输出（无测速字样） ==================

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
    print("🚀 ProxyIP 筛选（HTTP+CF头+WebSocket握手，无速度测试）", flush=True)
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
