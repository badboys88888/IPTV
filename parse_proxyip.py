#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Cloudflare ProxyIP 筛选器（全自动版）
- TCP 连通性检测
- WebSocket 握手检测（与您的 Worker 配置匹配）
- HTTPS 直接测试（通过节点访问 cp.cloudflare.com/generate_204）
- 自动查询 IP 地理位置（ipwho.is / freeipapi / ip-api，带缓存和限速）
- 输出带国家/运营商标签的节点列表，按国家分组、按延迟排序
- 无需任何外部二进制，可在 GitHub Actions 中稳定运行
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
INPUT_FILE = "proxyip/results.csv"          # 输入的 CSV 文件
OUTPUT_FILE = "proxyip_output.txt"          # 输出的节点列表
CACHE_FILE = "ip_cache.json"                # IP 地理位置缓存文件

# WebSocket 测试参数（与您的 Worker 配置一致）
TEST_HOST = "cloudflare.snippets1.dpdns.org"
TEST_PATH = "/?ed=2560"
TEST_UUID = "362cbd17-f2d0-4b37-8d2c-10a2a45ddefc"

# HTTPS 直接测试的目标 URL
TEST_URL = "https://cp.cloudflare.com/generate_204"

MAX_WORKERS = 30            # 并发数
CONNECT_TIMEOUT = 8         # TCP 连接超时（秒）
REQ_TIMEOUT = 15            # 请求超时（秒）
LATENCY_ROUNDS = 3          # 每轮测试次数（用于计算平均延迟和抖动）
MAX_AVG_LATENCY = 9000      # 最大允许平均延迟（毫秒）
MAX_JITTER = 9000           # 最大允许抖动（毫秒）

DEFAULT_PORTS = [443, 8443, 2053, 2083, 2087, 2096]   # 若未指定端口，尝试这些

# 地理查询限速（秒/次）
GEO_MIN_INTERVAL = 1.5

# ================== 国家与运营商映射表 ==================
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
    "oracle": "甲骨文云", "amazon": "亚马逊云", "google": "谷歌云", "microsoft": "Azure",
    "cloudflare": "Cloudflare", "alibaba": "阿里云", "digitalocean": "机房", "vultr": "机房",
    "sk broadband": "SK宽带", "korea telecom": "韩国电信", "kt corp": "韩国电信",
    "hkt": "香港电讯", "hkbn": "香港宽频", "pccw": "香港电讯",
    "private customer": "家宽", "private": "家宽", "customer": "家宽",
    "charter": "Spectrum", "frontier": "Frontier", "comcast": "康卡斯特",
    "verizon": "威瑞森", "at&t": "AT&T", "vodafone": "沃达丰",
    "hinet": "中华电信", "chunghwa": "中华电信", "twm": "台湾大哥大",
    "enterprise": "企宽",
}

# ================== 工具函数 ==================

def parse_ip_port(addr):
    """解析地址行，返回 [(ip, port), ...] 列表"""
    addr = addr.strip()
    # IPv6 带括号形式 [::1]:443
    if addr.startswith("["):
        end = addr.index("]")
        ip = addr[1:end]
        rest = addr[end+1:]
        port = int(rest[1:]) if rest.startswith(":") else 443
        return [(ip, port)]
    # IPv4 或域名带端口
    if ":" in addr:
        parts = addr.rsplit(":", 1)
        try:
            return [(parts[0], int(parts[1]))]
        except ValueError:
            pass
    # 未指定端口，尝试默认端口列表
    return [(addr, p) for p in DEFAULT_PORTS]

def tcp_ok(ip, port):
    """TCP 连通性测试"""
    try:
        family = socket.AF_INET6 if ":" in ip else socket.AF_INET
        s = socket.socket(family, socket.SOCK_STREAM)
        s.settimeout(CONNECT_TIMEOUT)
        s.connect((ip, port))
        s.close()
        return True
    except Exception:
        return False

def test_websocket(ip, port, timeout=5):
    """WebSocket 握手测试（不进行实际数据收发）"""
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

def direct_https_test(ip, port, timeout=10):
    """
    通过代理节点直接建立 TLS 连接，发送 GET 请求到 cp.cloudflare.com/generate_204
    返回 (成功, 延迟毫秒)
    """
    family = socket.AF_INET6 if ":" in ip else socket.AF_INET
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    sock = None
    t0 = time.perf_counter()
    try:
        sock = ctx.wrap_socket(
            socket.socket(family, socket.SOCK_STREAM),
            server_hostname="cp.cloudflare.com"
        )
        sock.settimeout(timeout)
        sock.connect((ip, port))

        req = (
            "GET /generate_204 HTTP/1.1\r\n"
            "Host: cp.cloudflare.com\r\n"
            "User-Agent: curl/8.0\r\n"
            "Connection: close\r\n\r\n"
        ).encode()
        sock.sendall(req)

        resp = b""
        while b"\r\n\r\n" not in resp:
            chunk = sock.recv(4096)
            if not chunk:
                break
            resp += chunk
        elapsed = (time.perf_counter() - t0) * 1000

        if not resp:
            return False, 9999
        status_line = resp.split(b"\r\n")[0].decode(errors="ignore")
        if "200" in status_line or "204" in status_line:
            return True, round(elapsed, 1)
        return False, 9999
    except Exception:
        return False, 9999
    finally:
        if sock:
            sock.close()

# ================== 单节点筛选 ==================

def filter_one(addr, region):
    """
    对一个地址进行完整检测（TCP + WebSocket + HTTPS 直接测试）
    返回 {"pass": bool, ...}
    """
    print(f"▸ {addr} 开始...", flush=True)
    candidates = parse_ip_port(addr)
    best = None

    for ip, port in candidates:
        # 1. TCP 连通性
        if not tcp_ok(ip, port):
            print(f"  ✗ TCP 不通 {ip}:{port}", flush=True)
            continue

        # 2. WebSocket 握手（多轮测试取平均延迟和抖动）
        samples = []
        for rnd in range(LATENCY_ROUNDS):
            ok, lat, info = websocket_measure(ip, port)   # 见下方辅助函数
            if ok:
                samples.append(lat)
            else:
                print(f"  ✗ {addr} 第{rnd+1}轮 WS 失败: {info}", flush=True)
                break
            time.sleep(0.05)
        else:
            avg = statistics.mean(samples)
            jitter = statistics.stdev(samples) if len(samples) > 1 else 0

            if avg > MAX_AVG_LATENCY or jitter > MAX_JITTER:
                print(f"  ✗ {addr} 延迟或抖动过高 (avg={avg:.0f}ms, jitter={jitter:.0f}ms)", flush=True)
                continue

            # 3. HTTPS 直接测试
            print(f"  ⟳ HTTPS 直接测试...", flush=True)
            ok, https_lat = direct_https_test(ip, port)
            if not ok:
                print(f"  ✗ HTTPS 直接测试失败 {ip}:{port}", flush=True)
                continue

            print(f"  ✓ {addr} 全部通过 (HTTPS延迟={https_lat:.0f}ms, WS avg={avg:.0f}ms)", flush=True)

            # 记录最佳节点（以 HTTPS 延迟为准）
            result = {
                "addr": f"{ip}:{port}",
                "ip": ip,
                "port": port,
                "latency": https_lat,
                "region": region,
            }
            if best is None or https_lat < best["latency"]:
                best = result

        # 继续尝试下一个端口（如果当前端口失败）
        continue

    if best:
        return {"pass": True, **best}
    else:
        print(f"  ✗ {addr} 所有端口不可用", flush=True)
        return {"pass": False, "addr": addr, "region": region}

def websocket_measure(ip, port):
    """
    返回 WebSocket 握手的 (成功, 延迟ms, 详情)
    用于多轮延迟采样
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
            s.close()
            if not resp:
                return (False, 9999, "空响应")
            line = resp.split(b"\r\n")[0].decode(errors="ignore")
            if line.startswith("HTTP/1.1 101"):
                return (True, round(elapsed, 1), "WS握手成功")
            else:
                return (False, 9999, f"WS状态码错误: {line[:30]}")
        except Exception as e:
            return (False, 9999, str(e)[:50])
        finally:
            s.close()

    ok, lat, d = _try(True)
    if ok:
        return ok, lat, d
    ok, lat, d = _try(False)
    return ok, lat, d

# ================== CSV 读取 ==================

def read_csv():
    """读取 proxyip/results.csv，返回 (ip, region) 列表"""
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

# ================== 地理位置查询（带缓存） ==================

def load_geo_cache():
    try:
        with open(CACHE_FILE, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
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

def org_cn(org):
    if not org:
        return "未知"
    for k, v in ORG_MAP.items():
        if k in org.lower():
            return v
    return org

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
    # 1. ipwho.is
    data = fetch_json(f"https://ipwho.is/{ip_only}")
    if data and data.get("success"):
        cc = data.get("country_code", "")
        country = COUNTRY_MAP.get(cc, data.get("country", cc or "未知"))
        org = org_cn(data.get("connection", {}).get("isp", ""))
    # 2. freeipapi.com
    if country == "未知":
        data = fetch_json(f"https://freeipapi.com/api/json/{ip_only}")
        if data:
            cc = data.get("countryCode", "")
            country = COUNTRY_MAP.get(cc, data.get("countryName", cc or "未知"))
            org = org_cn(data.get("asnOrganization", ""))
    # 3. ip-api.com
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
    """为通过节点附加国家/运营商信息，并返回按国家分组的列表"""
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
        country = info["country"]
        org = info["org"]
        groups[country].append({
            "addr": it["addr"],
            "org": org,
            "latency": it["latency"],
        })
    return groups

# ================== 输出 ==================

def save_output(passed):
    """按国家分组输出节点列表"""
    groups = geo_enrich(passed)
    lines = []
    total = 0
    for country, items in sorted(groups.items()):
        items.sort(key=lambda x: x["latency"])   # 按延迟升序
        lines.append(f"#{country}")
        for idx, it in enumerate(items, 1):
            org_part = it["org"] if it["org"] and it["org"] != "未知" else ""
            if org_part:
                label = f"{country}-{idx:03d}-{org_part}"
            else:
                label = f"{country}-{idx:03d}"
            lines.append(f"{it['addr']}#{label} ({it['latency']:.0f}ms)")
            total += 1
        lines.append("")
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print(f"✅ 通过 {total} 个节点 → {OUTPUT_FILE}", flush=True)

# ================== 主程序 ==================

def main():
    print("🚀 Cloudflare ProxyIP 筛选器 (TCP + WebSocket + HTTPS 直接测试)", flush=True)
    print(f"   白名单状态: HTTP 2xx/3xx，403 需要 CF 头", flush=True)
    print(f"   目标: {TEST_HOST}{TEST_PATH}", flush=True)
    proxies = read_csv()
    if not proxies:
        return

    passed = []
    failed = 0
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        futures = {ex.submit(filter_one, addr, region): addr for addr, region in proxies}
        for future in as_completed(futures):
            try:
                res = future.result()
                if res["pass"]:
                    passed.append(res)
                else:
                    failed += 1
            except Exception as e:
                failed += 1
                print(f"  ⚠ 异常 [{futures[future]}]: {e}", flush=True)

    print(f"\n📊 总计 {len(proxies)} | ✅ 通过 {len(passed)} | ❌ 淘汰 {failed}", flush=True)
    if passed:
        save_output(passed)
    else:
        print("❌ 无节点通过", flush=True)

if __name__ == "__main__":
    main()
