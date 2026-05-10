import asyncio
import aiohttp
import json
import os
import ipaddress

# === 核心配置 ===
CONFIG_PATH = 'config.json'
INPUT_IP = 'scan/udp.txt'
SCAN_CONCURRENCY = 2056        # 既然DEBUG通了，256-512并发是安全的
IPTV_PORTS = [4000, 4022, 8000, 8080, 8888, 9000, 9999] 

def log(msg):
    print(msg, flush=True)

async def verify_stream(session, node, test_udp):
    """深度拉流验证：只要能吐出非报错文本的数据就视为有效"""
    url = f"http://{node}/udp/{test_udp}"
    try:
        # 给 15 秒拉流时间，跨国传输慢
        async with session.get(url, timeout=15) as r:
            if r.status == 200:
                chunk = await r.content.read(1024 * 64)
                if len(chunk) > 500:
                    # 排除掉常见的报错 JSON/HTML 特征码
                    if b'{"rtn":' not in chunk and b'msg' not in chunk and b'<html>' not in chunk.lower():
                        return True
    except:
        pass
    return False

def save_to_repo(filename, node):
    """保存并去重"""
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
    """核心扫描逻辑"""
    
    # --- DEBUG 验证 ---
    if "瑞士" in prefer_region or "Swiss" in name:
        debug_node = "82.220.87.8:4022"
        try:
            async with session.get(f"http://{debug_node}/status", timeout=10) as r:
                log(f"DEBUG: 强连 {debug_node} 成功！状态码: {r.status}")
        except Exception as e:
            log(f"DEBUG: 强连失败，请检查网关。原因: {e}")

    if not os.path.exists(INPUT_IP):
        log(f"❌ 找不到网段文件: {INPUT_IP}")
        return

    all_ips = []
    is_target_region = False
    # 关键词归一化：去掉多余空格，转小写
    target_kw = str(prefer_region or name).lower().replace("组播","").replace("电信","").replace("联通","").strip()

    # 1. 匹配网段逻辑
    with open(INPUT_IP, 'r', encoding='utf-8') as f:
        for line in f:
            clean_line = line.strip()
            if not clean_line: continue
            if clean_line.startswith('#'):
                # 模糊匹配：# 辽宁 能匹配 辽宁电信组播
                label = clean_line.lower().replace('#','').strip()
                is_target_region = label in target_kw or target_kw in label
                continue
            if is_target_region:
                try:
                    net = ipaddress.IPv4Network(clean_line, strict=False)
                    all_ips.extend([str(ip) for ip in list(net)])
                except: continue

    if not all_ips:
        log(f"[-] [{name}] 未在 {INPUT_IP} 中匹配到关键词 [{target_kw}]，跳过")
        return

    total_pts = len(all_ips) * len(IPTV_PORTS)
    log(f"[*] [{name}] 启动探测，总点位: {total_pts}")
    
    # 2. 第一阶段：快速识别 (采用 DEBUG 模式：只要 200 OK 就算)
    alive_nodes = []
    sem = asyncio.Semaphore(SCAN_CONCURRENCY)
    done_count = 0

    async def check_node(ip, port):
        nonlocal done_count
        async with sem:
            node = f"{ip}:{port}"
            try:
                # 不再读取 body 内容，只要 header 响应快
                async with session.get(f"http://{node}/status", timeout=7.0) as r:
                    if r.status == 200:
                        log(f"  ✨ 发现开放源: {node}")
                        return node
            except: pass
            finally:
                done_count += 1
                if done_count % 1000 == 0:
                    log(f"  > 进度: {done_count}/{total_pts}")
            return None

    all_params = [(ip, p) for ip in all_ips for p in IPTV_PORTS]
    batch_size = 2000
    for i in range(0, len(all_params), batch_size):
        batch = all_params[i : i + batch_size]
        results = await asyncio.gather(*(check_node(ip, p) for ip, p in batch))
        alive_nodes.extend([r for r in results if r])

    log(f"[*] [{name}] 第一阶段结束，潜在点位: {len(alive_nodes)}")

    # 3. 第二阶段：精准拉流验证
    count = 0
    for node in alive_nodes:
        if await verify_stream(session, node, test_udp):
            if save_to_repo(name, node):
                log(f"  ✅ [{name}] 捕获有效源: {node}")
                count += 1
    log(f"[*] [{name}] 任务结束，新增: {count} 个")

async def main():
    if not os.path.exists(CONFIG_PATH):
        log(f"❌ 找不到 {CONFIG_PATH}")
        return

    with open(CONFIG_PATH, 'r', encoding='utf-8') as f:
        config_data = json.load(f)

    tasks = config_data if isinstance(config_data, list) else [config_data]

    headers = {"User-Agent": "VLC/3.0.18 LibVLC/3.0.18", "Accept": "*/*"}
    async with aiohttp.ClientSession(headers=headers) as session:
        for task in tasks:
            name = task.get('name')
            test_udp = task.get('test_udp')
            region = task.get('prefer_region') or name
            if name and test_udp:
                await run_scan(session, name, test_udp, region)

if __name__ == "__main__":
    asyncio.run(main())
