import asyncio
import aiohttp
import json
import os
import ipaddress

# === 核心配置 ===
CONFIG_PATH = 'config.json'
INPUT_IP = 'scan/udp.txt'
SCAN_CONCURRENCY = 1024       # 降低并发提高跨国扫描稳定性
IPTV_PORTS = [4000, 4022, 8000, 8080, 8888, 9000, 9999]

def log(msg):
    print(msg, flush=True)

async def verify_stream(session, node, test_udp):
    """
    极简拉流验证：只要能吐出非报错文本的数据就视为有效
    """
    url = f"http://{node}/udp/{test_udp}"
    # 尝试 2 次，防止网络瞬断
    for _ in range(2):
        try:
            async with session.get(url, timeout=15) as r:
                if r.status == 200:
                    # 读取一小段数据块
                    chunk = await r.content.read(1024 * 64)
                    if len(chunk) > 500:
                        # 排除掉常见的报错 JSON/HTML 特征码
                        if b'{"rtn":' not in chunk and b'msg' not in chunk and b'<html>' not in chunk.lower():
                            return True
        except:
            await asyncio.sleep(0.5)
            continue
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
    if not os.path.exists(INPUT_IP):
        log(f"❌ 找不到网段文件: {INPUT_IP}")
        return

    all_ips = []
    is_target_region = False
    
    # 1. 匹配网段逻辑（支持模糊匹配，不区分大小写）
    target_kw = (prefer_region or name).lower().strip()
    with open(INPUT_IP, 'r', encoding='utf-8') as f:
        for line in f:
            clean_line = line.strip()
            if not clean_line: continue
            if clean_line.startswith('#'):
                # 只要 # 后的文字包含关键词即开闸，如 "# 辽宁电信" 匹配 "辽宁"
                is_target_region = target_kw in clean_line.lower()
                continue
            if is_target_region:
                try:
                    net = ipaddress.IPv4Network(clean_line, strict=False)
                    all_ips.extend([str(ip) for ip in list(net)])
                except: continue

    if not all_ips:
        log(f"[-] [{name}] 未在 {INPUT_IP} 中匹配到 [{target_kw}] 段，跳过")
        return

    total_pts = len(all_ips) * len(IPTV_PORTS)
    log(f"[*] [{name}] 任务启动，点位: {total_pts} (关键词: {target_kw})")
    
    # 2. 第一阶段：快速识别 status 页面
    alive_nodes = []
    sem = asyncio.Semaphore(SCAN_CONCURRENCY)
    done_count = 0

    async def check_node(ip, port):
        nonlocal done_count
        async with sem:
            node = f"{ip}:{port}"
            try:
                # 增加超时到 5s 确保海外握手成功
                async with session.get(f"http://{node}/status", timeout=5.0) as r:
                    if r.status == 200:
                        text = await r.text()
                        # 识别标准 udpxy 页面
                        if "udpxy" in text.lower() and "108545" not in text:
                            log(f"  ✨ 发现 udpxy 活口: {node}")
                            return node
            except: pass
            finally:
                done_count += 1
                if done_count % 1000 == 0:
                    log(f"  > 进度: {done_count}/{total_pts}")
            return None

    # 分批执行
    all_params = [(ip, p) for ip in all_ips for p in IPTV_PORTS]
    batch_size = 2000
    for i in range(0, len(all_params), batch_size):
        batch = all_params[i : i + batch_size]
        results = await asyncio.gather(*(check_node(ip, p) for ip, p in batch))
        alive_nodes.extend([r for r in results if r])

    log(f"[*] [{name}] 第一阶段结束，潜在点位: {len(alive_nodes)}")

    # 3. 第二阶段：精准拉流
    count = 0
    for node in alive_nodes:
        if await verify_stream(session, node, test_udp):
            if save_to_repo(name, node):
                log(f"  ✅ [{name}] 捕获有效源: {node}")
                count += 1
            else:
                log(f"  ➖ [{name}] 已存在: {node}")
    log(f"[*] [{name}] 扫描结束，新增: {count} 个")

async def main():
    if not os.path.exists(CONFIG_PATH):
        log(f"❌ 找不到 {CONFIG_PATH}")
        return

    with open(CONFIG_PATH, 'r', encoding='utf-8') as f:
        config_data = json.load(f)

    tasks = config_data if isinstance(config_data, list) else [config_data]

    # 模拟真实播放器头，防止被运营商或 WAF 屏蔽
    headers = {
        "User-Agent": "VLC/3.0.18 LibVLC/3.0.18",
        "Accept": "*/*"
    }
    
    async with aiohttp.ClientSession(headers=headers) as session:
        for task in tasks:
            name = task.get('name')
            test_udp = task.get('test_udp')
            # 优先用 prefer_region 匹配
            region = task.get('prefer_region') or name
            
            if name and test_udp:
                await run_scan(session, name, test_udp, region)

if __name__ == "__main__":
    asyncio.run(main())
