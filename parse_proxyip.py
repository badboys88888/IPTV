#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Cloudflare ProxyIP + sing-box 真连接筛选 (宽松模式：无 ECH + 跳过证书验证)
功能：
1. TCP 检测
2. WebSocket 检测
3. sing-box 真连接检测 (ECH 关闭、insecure true)
4. 地理位置自动标注（带缓存）
"""

import csv
import io
import os
import ssl
import time
import json
import socket
import tempfile
import subprocess
import urllib.request
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

# ================== 配置 ==================
INPUT_FILE = "proxyip/results.csv"
OUTPUT_FILE = "proxyip_output.txt"
CACHE_FILE = "ip_cache.json"

TEST_HOST = "cloudflare.snippets1.dpdns.org"
TEST_PATH = "/?ed=2560"
TEST_UUID = "362cbd17-f2d0-4b37-8d2c-10a2a45ddefc"

SINGBOX_BIN = "./sing-box"

MAX_WORKERS = 30
CONNECT_TIMEOUT = 8
DEFAULT_PORTS = [443, 8443, 2053, 2083, 2087, 2096]

GEO_MIN_INTERVAL = 1.5

# ================== 地理映射 ==================
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
        family = socket.AF_INET6 if ":" in ip else socket.AF_INET
        s = socket.socket(family, socket.SOCK_STREAM)
        s.settimeout(CONNECT_TIMEOUT)
        s.connect((ip, port))
        s.close()
        return True
    except Exception:
        return False

# ================== WebSocket 检测 ==================

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

# ================== sing-box 宽松模板 ==================
# 关键修改：关闭 ECH，跳过证书验证，保留 utls（可选）

SINGBOX_TEMPLATE = {
    "log": {"disabled": True},
    "dns": {"servers": [{"tag": "google", "address": "8.8.8.8"}]},
    "inbounds": [
        {
            "type": "socks",
            "tag": "socks-in",
            "listen": "127.0.0.1",
            "listen_port": 2080
        }
    ],
    "outbounds": [
        {
            "type": "vless",
            "tag": "proxy",
            "server": "",
            "server_port": 443,
            "uuid": TEST_UUID,
            "tls": {
                "enabled": True,
                "server_name": TEST_HOST,
                "insecure": True,                # 跳过证书验证 (对应 Clash skip-cert-verify: true)
                "utls": {
                    "enabled": True,
                    "fingerprint": "chrome"
                }
                # 不再包含 ech 字段，相当于 ech 关闭
            },
            "transport": {
                "type": "ws",
                "path": TEST_PATH,
                "headers": {"Host": TEST_HOST}
            }
        },
        {"type": "direct", "tag": "direct"}
    ],
    "route": {
        "rules": [{"protocol": "dns", "outbound": "direct"}],
        "final": "proxy"
    }
}

def singbox_real_test(ip, port):
    config = json.loads(json.dumps(SINGBOX_TEMPLATE))
    config["outbounds"][0]["server"] = ip
    config["outbounds"][0]["server_port"] = port

    with tempfile.NamedTemporaryFile(
        mode="w", delete=False, suffix=".json", encoding="utf-8"
    ) as f:
        json.dump(config, f, ensure_ascii=False, indent=2)
        cfg_path = f.name

    proc = None
    try:
        proc = subprocess.Popen(
            [SINGBOX_BIN, "run", "-c", cfg_path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        time.sleep(3)

        proxy_support = urllib.request.ProxyHandler({
            "http": "socks5://127.0.0.1:2080",
            "https": "socks5://127.0.0.1:2080"
        })
        opener = urllib.request.build_opener(proxy_support)
        t0 = time.perf_counter()
        req = urllib.request.Request(
            "https://cp.cloudflare.com/generate_204",
            headers={"User-Agent": "curl/8.0"}
        )
        with opener.open(req, timeout=10) as resp:
            code = resp.getcode()
        latency = (time.perf_counter() - t0) * 1000
        if code in [204, 200]:
            return True, round(latency, 1)
        return False, 9999
    except Exception:
        return False, 9999
    finally:
        if proc:
            proc.kill()
        try:
            os.remove(cfg_path)
        except Exception:
            pass

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

# ================== 单节点检测 ==================

def filter_one(addr):
    print(f"▸ {addr} 开始...", flush=True)
    candidates = parse_ip_port(addr)
    best = None

    for ip, port in candidates:
        if not tcp_ok(ip, port):
            print(f"  ✗ TCP 不通 {ip}:{port}", flush=True)
            continue
        if not test_websocket(ip, port):
            print(f"  ✗ WS 失败 {ip}:{port}", flush=True)
            continue
        print(f"  ✓ WS 成功 {ip}:{port}", flush=True)

        print(f"  ⟳ sing-box 真连接测试...", flush=True)
        ok, latency = singbox_real_test(ip, port)
        if not ok:
            print(f"  ✗ sing-box 失败 {ip}:{port}", flush=True)
            continue
        print(f"  ✓ sing-box 成功 {latency:.0f}ms", flush=True)

        result = {
            "addr": f"{ip}:{port}",
            "ip": ip,
            "port": port,
            "latency": latency
        }
        if best is None or latency < best["latency"]:
            best = result

    if best:
        return {"pass": True, **best}
    return {"pass": False, "addr": addr}

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
        proxies.append(ip)
    print(f"📊 候选 {len(proxies)} 个", flush=True)
    return proxies

# ================== 输出带国家/运营商标签 ==================

def save_output_with_geo(passed_results):
    if not passed_results:
        print("❌ 无节点通过", flush=True)
        return

    # 按 IP 聚合
    unique_ips = {}
    for item in passed_results:
        ip = item["ip"]
        if ip not in unique_ips:
            unique_ips[ip] = []
        unique_ips[ip].append(item)

    cache = load_geo_cache()
    uncached_ips = [ip for ip in unique_ips.keys() if ip not in cache]
    if uncached_ips:
        print(f"🌍 开始查询 {len(uncached_ips)} 个新 IP 的地理位置（限速 {GEO_MIN_INTERVAL}s/次）...", flush=True)
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = {executor.submit(query_ip_info, ip, cache): ip for ip in uncached_ips}
            for future in as_completed(futures):
                ip_only, country, org = future.result()
                print(f"  🌍 {ip_only} → {country} / {org}", flush=True)
        save_geo_cache(cache)

    groups = defaultdict(list)
    for ip, items in unique_ips.items():
        info = cache.get(ip, {"country": "未知", "org": "未知"})
        country = info["country"]
        org = info["org"]
        for item in items:
            groups[country].append({
                "addr": f"{item['ip']}:{item['port']}",
                "org": org,
                "latency": item["latency"]
            })

    lines = []
    total = 0
    for country in sorted(groups.keys()):
        items = groups[country]
        items.sort(key=lambda x: x["latency"])
        lines.append(f"#{country}")
        for idx, it in enumerate(items, 1):
            org_part = it["org"] if it["org"] and it["org"] != "未知" else ""
            label = f"{country}-{idx:03d}-{org_part}" if org_part else f"{country}-{idx:03d}"
            lines.append(f"{it['addr']}#{label} ({it['latency']:.0f}ms)")
            total += 1
        lines.append("")

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print(f"\n✅ 通过 {total} 个节点 → {OUTPUT_FILE}", flush=True)

# ================== 主程序 ==================

def main():
    print("\n🚀 Cloudflare ProxyIP 真连接筛选 (宽松模式：无ECH + 跳过TLS验证)\n", flush=True)
    proxies = read_csv()
    if not proxies:
        return

    passed = []
    failed = 0
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        futures = {ex.submit(filter_one, addr): addr for addr in proxies}
        for future in as_completed(futures):
            try:
                res = future.result()
                if res["pass"]:
                    passed.append(res)
                else:
                    failed += 1
            except Exception as e:
                failed += 1
                print(f"⚠ 异常 {futures[future]}: {e}", flush=True)

    print(f"\n📊 总计 {len(proxies)} | ✅ 通过 {len(passed)} | ❌ 淘汰 {failed}", flush=True)
    if passed:
        save_output_with_geo(passed)
    else:
        print("❌ 无节点通过", flush=True)

if __name__ == "__main__":
    main()
