import asyncio
import aiohttp
import json
import os
import ipaddress
import sys

# === 核心配置 ===
CONFIG_PATH = 'config.json'
INPUT_IP = 'scan/udp.txt'
SCAN_CONCURRENCY = 1024       
IPTV_PORTS = [4000, 4022, 8000, 8080, 8888, 9000, 9999]

def log(msg):
    """定义一个实时刷新的打印函数"""
    print(msg, flush=True)

async def verify_stream(session, node, test_udp):
    for path in ["udp", "rtp"]:
        url = f"http://{node}/{path}/{test_udp}"
        try:
            async with session.get(url, timeout=5) as r:
                ctype = r.headers.get('Content-Type', '').lower()
                if "json" in ctype or "text" in ctype or "html" in ctype:
                    continue
                if r.status == 200:
                    content = await r.content.read(128 * 1024)
                    if len(content) > 10000:
                        return True
        except:
            continue
    return False

def save_to_repo(filename, node):
    target_file = f"{filename}.txt"
    existing = set()
    if os.path.exists(target_file):
        with open(target_file, 'r', encoding='utf-8') as f:
            existing = {line.strip() for line in f if line.strip() and not line.startswith('#')}
    if node not in existing:
        with open(target_file, 'a', encoding='utf-8') as f:
            if not existing:
                f.write(f"# {filename}\n")
            f.write(f"{node}\n")
        return True
    return False

async def run_scan(session, name, test_udp, prefer_region):
    if not os.path.exists(INPUT_IP):
        log(f"❌ 找不到文件: {INPUT_IP}")
        return

    all_ips = []
    is_target_region = False
    with open(INPUT_IP, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line: continue
            if line.startswith('#'):
                # 修改匹配逻辑：支持 # 福建 这种格式
                is_target_region = (prefer_region and prefer_region in line)
                continue
            if is_target_region:
                try:
                    net = ipaddress.IPv4Network(line, strict=False)
                    all_ips.extend([str(ip) for ip in list(net)])
                except: continue

    if not all_ips:
        log(f"[-] [{name}] 未匹配到 [{prefer_region}] 标签，跳过")
        return

    total_points = len(all_ips) * len(IPTV_PORTS)
    log(f"[*] [{name}] 启动任务，总点位: {total_points}")
    
    alive_nodes = []
    sem = asyncio.Semaphore(SCAN_CONCURRENCY)
    counter = 0

    async def check_node(ip, port):
        nonlocal counter
        async with sem:
            node = f"{ip}:{port}"
            try:
                async with session.get(f"http://{node}/status", timeout=1.5) as r:
                    if r.status == 200:
                        text = await r.text()
                        if "udpxy" in text.lower() and "108545" not in text:
                            log(f"  ✨ 发现疑似源: {node}")
                            return node
            except: pass
            finally:
                counter += 1
                # 每完成 1000 个打印一次进度，不再沉默
                if counter % 1000 == 0:
                    log(f"  > 进度: {counter}/{total_points}")
            return None

    all_params = [(ip, p) for ip in all_ips for p in IPTV_PORTS]
    
    # 分批执行（每批 2000 个协程），保持日志流畅
    batch_size = 2000
    for i in range(0, len(all_params), batch_size):
        batch = all_params[i : i + batch_size]
        results = await asyncio.gather(*(check_node(ip, p) for ip, p in batch))
        alive_nodes.extend([r for r in results if r])

    log(f"[*] [{name}] 探测结束，潜在点位: {len(alive_nodes)}")

    count = 0
    for node in alive_nodes:
        if await verify_stream(session, node, test_udp):
            if save_to_repo(name, node):
                log(f"  ✅ [{name}] 捕获成功: {node}")
                count += 1
    log(f"[*] [{name}] 扫描完成，本次新增: {count}")

async def main():
    if not os.path.exists(CONFIG_PATH):
        log(f"❌ 找不到 {CONFIG_PATH}")
        return

    with open(CONFIG_PATH, 'r', encoding='utf-8') as f:
        config_data = json.load(f)

    tasks = config_data if isinstance(config_data, list) else [config_data]

    # 设置请求头模拟真实环境
    headers = {"User-Agent": "VLC/3.0.18 LibVLC/3.0.18"}
    async with aiohttp.ClientSession(headers=headers) as session:
        for task in tasks:
            name = task.get('name', '默认分类')
            test_udp = task.get('test_udp')
            region = task.get('prefer_region') or name
            if not test_udp: continue
            await run_scan(session, name, test_udp, region)

if __name__ == "__main__":
    asyncio.run(main())
