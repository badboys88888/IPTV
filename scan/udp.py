from __future__ import annotations

import asyncio
import aiohttp
import json
import os
import ipaddress
import time
from typing import Dict, List, Optional, Set

# =====================================================================
#  核心配置
# =====================================================================
CONFIG_PATH   = 'config.json'
INPUT_IP      = 'scan/udp.txt'

SCAN_CONCURRENCY = 5120          # TCPConnector 配置后实际生效，不要超过 1024
STREAM_VERIFY_CONCURRENCY = 64  # 拉流验证慢，并发不用高

# udpxy 常见端口，越靠前命中率越高
IPTV_PORTS = [4000, 4022, 8888, 8080, 9000, 8000, 9999, 5000, 7777]

# 探活时尝试的路径列表（按命中率排序）
# 第一阶段探活：认定"活着"的 HTTP 状态码
# 流验证：最小有效字节数（64KB）
MIN_STREAM_BYTES = 1024 * 4   # 降低到 4KB，境外拉国内流超时严重，能收到少量数据就算有效

# =====================================================================
#  工具函数
# =====================================================================

def log(msg: str):
    ts = time.strftime('%H:%M:%S')
    print(f"[{ts}] {msg}", flush=True)


def load_config() -> list[dict]:
    if not os.path.exists(CONFIG_PATH):
        raise FileNotFoundError(f"找不到配置文件: {CONFIG_PATH}")
    with open(CONFIG_PATH, 'r', encoding='utf-8') as f:
        data = json.load(f)
    return data if isinstance(data, list) else [data]


def save_node(filename: str, node: str) -> bool:
    """去重写入，返回是否为新增"""
    target = f"{filename}.txt"
    existing: set[str] = set()
    if os.path.exists(target):
        with open(target, 'r', encoding='utf-8') as f:
            existing = {ln.strip() for ln in f if ln.strip() and not ln.startswith('#')}
    if node in existing:
        return False
    with open(target, 'a', encoding='utf-8') as f:
        if not existing:          # 首次写入加表头
            f.write(f"# {filename}\n")
        f.write(f"{node}\n")
    return True


def load_ips_for_region(region_kw: str) -> list[str]:
    """
    从 INPUT_IP 文件按 # 注释行匹配区域关键词，
    返回该区域下所有 IP 列表（展开 CIDR）。
    """
    if not os.path.exists(INPUT_IP):
        log(f"❌ 找不到网段文件: {INPUT_IP}")
        return []

    kw = region_kw.lower() \
        .replace('组播', '').replace('电信', '') \
        .replace('联通', '').replace('移动', '').strip()

    all_ips: list[str] = []
    in_region = False

    with open(INPUT_IP, 'r', encoding='utf-8') as f:
        for raw in f:
            line = raw.strip()
            if not line:
                continue
            if line.startswith('#'):
                label = line.lstrip('#').strip().lower()
                in_region = (kw in label) or (label in kw)
                continue
            if in_region:
                try:
                    net = ipaddress.IPv4Network(line, strict=False)
                    all_ips.extend(str(ip) for ip in net)
                except ValueError:
                    continue

    return all_ips

# =====================================================================
#  阶段一：快速探活
# =====================================================================

# 已知误报端口黑名单（非 IPTV 专属端口，且 IPTV 扫描列表里没有这些端口）
PORT_BLACKLIST = {
    5000, 5001,   # 群晖 NAS DSM
    3000, 3001,   # Grafana / Node 开发服务
    8443, 443,    # HTTPS
    9090,         # Prometheus
    # 注意：8888/8080/8000/9000/9999/4000/4022 是常见 udpxy 端口，不能加黑名单
}

# 误报 body 特征：命中即排除
# 只过滤非常明确的误报，避免误杀魔改版 udpxy
FALSE_POSITIVE_SIGNS = [
    b"synology", b"diskstation",   # 群晖
    b"<!doctype html",             # 标准 HTML 页面（注意：不能只判断 <html，udpxy 有些版本 body 含 html 字样）
    b"unauthorized",               # 认证墙
]


async def probe_alive(session: aiohttp.ClientSession, ip: str, port: int) -> str | None:
    """
    探活策略（宽进严出，误报交给阶段二拉流验证过滤）：
    1. 端口黑名单：已知非 IPTV 端口直接跳过
    2. 请求 /status：200 且 body 不含误报特征 → 存活
    3. /status 不通：尝试 /udp/ /rtp/ 路径，200/301/302 → 存活
    返回 "ip:port" 或 None。
    """
    # 黑名单端口直接跳过
    if port in PORT_BLACKLIST:
        return None

    node = f"{ip}:{port}"

    # --- 优先：/status 200 + 排除误报 body ---
    try:
        async with session.get(
            f"http://{node}/status",
            timeout=aiohttp.ClientTimeout(total=5),
            allow_redirects=False,
        ) as r:
            if r.status == 200:
                body = (await r.content.read(256)).lower()
                if not any(fp in body for fp in FALSE_POSITIVE_SIGNS):
                    return node   # 通过：是 IPTV 代理的概率很高
    except Exception:
        pass

    # --- 备用：/udp/ /rtp/ 有响应即可，剩下交给拉流验证 ---
    for path in ("/udp/", "/rtp/"):
        try:
            async with session.get(
                f"http://{node}{path}",
                timeout=aiohttp.ClientTimeout(total=5),
                allow_redirects=False,
            ) as r:
                if r.status in {200, 301, 302}:
                    return node
        except Exception:
            pass

    return None


async def stage1_scan(
    session: aiohttp.ClientSession,
    all_ips: list[str],
    name: str,
) -> list[str]:
    """并发探活，返回存活节点列表"""
    sem       = asyncio.Semaphore(SCAN_CONCURRENCY)
    all_tasks = [(ip, p) for ip in all_ips for p in IPTV_PORTS]
    total     = len(all_tasks)
    done      = 0
    alive: list[str] = []

    log(f"[{name}] 阶段一：探活 {len(all_ips)} 个 IP × {len(IPTV_PORTS)} 端口 = {total} 点位")

    async def _probe(ip, port):
        nonlocal done
        async with sem:
            result = await probe_alive(session, ip, port)
            done += 1
            if done % 2000 == 0:
                log(f"  [{name}] 进度 {done}/{total}，已发现 {len(alive)} 个活跃节点")
            if result:
                log(f"  [{name}] ✨ 活跃: {result}")
            return result

    batch = 3000
    for i in range(0, total, batch):
        chunk   = all_tasks[i : i + batch]
        results = await asyncio.gather(*(_probe(ip, p) for ip, p in chunk))
        alive.extend(r for r in results if r)

    log(f"[{name}] 阶段一完成，活跃节点: {len(alive)}")
    return alive

# =====================================================================
#  阶段二：精准拉流验证
# =====================================================================

# 判定为错误响应的特征字节（只检查前 256 字节，避免误杀正常 TS 流）
ERROR_SIGNATURES = [b'{"rtn":', b'<html>', b'<HTML>', b'{"error"', b'{"code":']


async def verify_stream(
    session: aiohttp.ClientSession,
    node: str,
    test_udp: str,
) -> bool:
    """
    拉流验证：
    - HTTP 200
    - 前 256 字节不含错误特征
    - 收到 ≥ MIN_STREAM_BYTES 字节
    同时打印详细调试信息，方便排查失败原因。
    """
    url = f"http://{node}/udp/{test_udp}"
    try:
        async with session.get(
            url,
            timeout=aiohttp.ClientTimeout(total=30, connect=8),
        ) as r:
            if r.status != 200:
                log(f"  [验证失败] {node} 状态码={r.status} url={url}")
                return False
            header_chunk = await r.content.read(256)
            header_lower = header_chunk.lower()
            for sig in ERROR_SIGNATURES:
                if sig in header_lower:
                    log(f"  [验证失败] {node} 命中错误特征={sig} body前256={header_chunk[:80]}")
                    return False
            remaining = await r.content.read(MIN_STREAM_BYTES - len(header_chunk))
            total_read = len(header_chunk) + len(remaining)
            if total_read < MIN_STREAM_BYTES:
                log(f"  [验证失败] {node} 数据量不足 {total_read}/{MIN_STREAM_BYTES} bytes")
                return False
            return True
    except Exception as e:
        log(f"  [验证失败] {node} 异常={type(e).__name__}: {e} url={url}")
        return False


async def stage2_verify(
    session: aiohttp.ClientSession,
    alive_nodes: list[str],
    test_udp: str,
    name: str,
) -> int:
    """并发验证，返回新增有效源数量"""
    sem   = asyncio.Semaphore(STREAM_VERIFY_CONCURRENCY)
    count = 0

    log(f"[{name}] 阶段二：验证 {len(alive_nodes)} 个节点的真实流")

    async def _verify(node):
        nonlocal count
        async with sem:
            ok = await verify_stream(session, node, test_udp)
            if ok:
                if save_node(name, node):
                    log(f"  [{name}] ✅ 有效源: {node}")
                    count += 1

    await asyncio.gather(*(_verify(n) for n in alive_nodes))
    return count

# =====================================================================
#  主扫描流程
# =====================================================================

async def run_task(session: aiohttp.ClientSession, task: dict):
    name       = task.get('name', '未命名')
    test_udp   = task.get('test_udp', '')
    region     = task.get('prefer_region') or name

    if not test_udp:
        log(f"[{name}] ⚠️  缺少 test_udp，跳过")
        return

    log(f"\n{'='*60}")
    log(f"任务: {name}  |  区域关键词: {region}  |  测试流: {test_udp}")
    log(f"{'='*60}")

    # 加载 IP 列表
    all_ips = load_ips_for_region(region)
    if not all_ips:
        log(f"[{name}] ❌ 未匹配到任何 IP，请检查 {INPUT_IP} 中的注释关键词")
        return
    log(f"[{name}] 已加载 {len(all_ips)} 个 IP 地址")

    # 阶段一：探活
    alive_nodes = await stage1_scan(session, all_ips, name)
    if not alive_nodes:
        log(f"[{name}] ⚠️  阶段一未发现任何活跃节点，任务结束")
        return

    # 阶段二：验证
    new_count = await stage2_verify(session, alive_nodes, test_udp, name)
    log(f"[{name}] 🎉 任务结束，本次新增有效源: {new_count} 个\n")


async def main():
    tasks = load_config()
    log(f"加载到 {len(tasks)} 个扫描任务")

    connector = aiohttp.TCPConnector(
        limit           = 0,           # 不限制全局连接数（由 Semaphore 控制）
        ttl_dns_cache   = 300,
        enable_cleanup_closed = True,
        force_close     = True,        # 避免连接池污染
    )
    headers = {
        "User-Agent": "VLC/3.0.18 LibVLC/3.0.18",
        "Accept":     "*/*",
    }
    async with aiohttp.ClientSession(
        connector = connector,
        headers   = headers,
    ) as session:
        for task in tasks:
            await run_task(session, task)

    log("✅ 所有任务完成")


if __name__ == "__main__":
    asyncio.run(main())
