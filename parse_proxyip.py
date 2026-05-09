#!/usr/bin/env python3
"""
Cloudflare ProxyIP 筛选 - Clash 完全兼容版
- HTTP 连通性 + WebSocket 握手
- 严格 TLS 证书验证（模拟 Clash skip-cert-verify=false）
- WebSocket 数据帧收发测试（验证真实数据通道）
- 延迟+抖动评估
- 自动地理位置映射
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

TEST_HOST = "cloudflare.snippets1.dpdns.org"   # 您的 Worker 域名
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

# ---- 新增：模拟 Clash 的严格 TLS 校验 ----
# 如果您的 Clash 配置中 skip-cert-verify: false，请设置 STRICT_TLS_VERIFY = True
# 如果您的 Clash 中跳过了证书校验，可以保持 False（与原有脚本行为一致）
STRICT_TLS_VERIFY = True   # 改为 True 以模拟 Clash 严格证书检查

# ---- 新增：WebSocket 数据测试配置 ----
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
                    # 严格证书验证，与 Clash skip-cert-verify=false 行为一致
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
            return (False, 9999, f"TLS 证书校验失败: {e}")
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

def send_websocket_frame(sock, payload, opcode=0x81):  # 0x81 = 文本帧（掩码位=1）
    """发送带掩码的 WebSocket 文本帧"""
    length = len(payload)
    frame = bytearray()
    frame.append(opcode)  # FIN=1, opcode=0x1 (文本)
    mask_bit = 0x80
    if length <= 125:
        frame.append(mask_bit | length)
    elif length <= 65535:
        frame.append(mask_bit | 126)
        frame.extend(length.to_bytes(2, byteorder='big'))
    else:
        frame.append(mask_bit | 127)
        frame.extend(length.to_bytes(8, byteorder='big'))
    # 生成4字节掩码
    mask = bytes([0x12, 0x34, 0x56, 0x78])  # 固定掩码，仅用于测试
    frame.extend(mask)
    masked_payload = bytearray(payload, 'utf-8')
    for i in range(len(masked_payload)):
        masked_payload[i] ^= mask[i % 4]
    frame.extend(masked_payload)
    sock.sendall(frame)

def recv_websocket_frame(sock, timeout):
    """接收 WebSocket 帧，解掩码并返回 payload 字符串"""
    sock.settimeout(timeout)
    try:
        # 读取2字节头部
        header = sock.recv(2)
        if len(header) < 2:
            return None
        byte1, byte2 = header[0], header[1]
        # 检查 FIN 和 opcode
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
        else:
            return None
    except Exception:
        return None

def test_websocket_data(ip, port, timeout=5):
    """
    完整 WebSocket 测试：握手 + 发送 ping 并期望收到 pong
    返回 (成功, 详细信息)
    """
    family = socket.AF_INET6 if ":" in ip else socket.AF_INET
    # 1. 发送握手请求
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
        if STRICT_TLS_VERIFY:
            ctx = ssl.create_default_context()
            ctx.check_hostname = True
            ctx.verify_mode = ssl.CERT_REQUIRED
        else:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        sock = ctx.wrap_socket(socket.socket(family, socket.SOCK_STREAM), server_hostname=TEST_HOST)
        sock.settimeout(timeout)
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

        # 2. 发送 ping 并等待 pong
        send_websocket_frame(sock, WS_PING_MESSAGE)
        pong = recv_websocket_frame(sock, timeout)
        if pong is None:
            return False, "WebSocket 数据接收超时"
        if WS_PONG_MESSAGE not in pong:
            return False, f"收到非预期响应: {pong}"

        return True, "WebSocket 数据通道正常"
    except ssl.SSLCertVerificationError as e:
        return False, f"TLS 证书校验失败: {e}"
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

            # 原 WebSocket 升级测试（保留）
            # 改为使用数据测试，因为数据测试已包含升级过程
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

# ================== CSV 读取、地理位置、输出保持不变（复用您原来的代码）==================

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

# ...（此处省略 COUNTRY_MAP, ORG_MAP, org_cn, load_geo_cache, save_geo_cache, fetch_json, query_ip_info, geo_enrich, save_output, main 等函数，这些函数与您原脚本完全相同，只需将 geoenrich 中的抖动字段保留即可，这里不重复粘贴以节省篇幅，但实际使用时必须完整复制）...

# 注意：由于篇幅限制，我无法在回答中重复全部 600 行代码。您可以直接将上述增强部分（特别是 filter_one 和新增的 WebSocket 帧函数）替换到您的原始脚本中，并保留所有未变动的函数（如 read_csv, geo_enrich, save_output 等）。
