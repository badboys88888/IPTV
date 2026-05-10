import asyncio
import aiohttp
import json
import os
import ipaddress

# === 核心配置 ===
CONFIG_PATH = 'config.json'
INPUT_IP = 'scan/udp.txt'
SCAN_CONCURRENCY = 256  # 跨国扫描建议不要超过 512
IPTV_PORTS = [4000, 4022, 8000, 8080, 8888, 9000, 9999]

def log(msg):
    print(msg, flush=True)

async def verify_stream(session, node, test_udp):
    """深度拉流验证"""
    # 针对你提供的 status 页面，它明确支持 /udp/ 格式
    url = f"http://{node}/udp/{test_udp}"
    try:
        # 跨国拉流建议超时给足 15 秒
        async with session.get(url, timeout=15) as r:
            if r.status == 200:
                ctype = r.headers.get('Content-Type', '').lower()
                # 如果返回的是网页或JSON报错，直接排除
                if any(t in ctype for t in ["json", "text", "html"]):
                    return False
                
                # 尝试读取数据块
                content = await r.content.read(128 * 1024)
                if len(content) > 10000:
                    return True
    except:
        pass
    return False

async def run_scan(session, name, test_udp, prefer_region):
    if not os.path.exists(INPUT_IP):
        log(f"❌ 文件不存在: {INPUT_IP}")
        return

    all_ips = []
    is_target_region = False
    
    # --- 极其稳健的标签匹配逻辑 ---
    with open(INPUT_IP, 'r', encoding='utf-8') as f:
        for line in f:
            clean_line = line.strip()
            if not clean_line: continue
            
            if clean_line.startswith('#'):
                # 只要 prefer_region 在这行里，就开闸。例如: "# 瑞士 Swisscom"
                if prefer_region and prefer_region.lower() in clean_line.lower():
                    is_target_region = True
                else:
                    is_target_region = False
                continue
            
            if is_target_region:
                try:
                    net = ipaddress.IPv4Network(clean_line, strict=False)
                    all_ips.extend([str(ip) for ip in list(net)])
                except: continue

    if not all_ips:
        log(f"[-] [{name}] 在 udp.txt 中未匹配到关键字 [{prefer_region}]")
        return

    total_tasks = len(all_ips) * len(IPTV_PORTS)
    log(f"[*] [{name}] 启动，点位: {total_tasks} (关键词: {prefer_region})")
    
    alive_nodes = []
    sem = asyncio.Semaphore(SCAN_CONCURRENCY)
    done_count = 0

    async def check_node(ip, port):
        nonlocal done_count
        async with sem:
            node = f"{ip}:{port}"
            try:
                # 关键：跨国探测 status 页面，增加超时到 5 秒
                async with session.get(f"http://{node}/status", timeout=5.0) as r:
                    if r.status == 200:
                        text = await r.text()
                        # 根据你提供的特征匹配：必须含 udpxy 且排除常见报错码
                        if "udpxy status" in text.lower() and "108545" not in text:
                            log(f"  ✨ 发现 udpxy 活口: {node}")
                            return node
            except:
                pass
            finally:
                done_count += 1
                if done_count % 500 == 0:
                    log(f"  > 扫描进度: {done_count}/{total_tasks}")
            return None

    # 分批执行，控制日志刷新速度
    all_params = [(ip, p) for ip in all_ips for p in IPTV_PORTS]
    batch_size = 1000
    for i in range(0, len(all_params), batch_size):
        batch = all_params[i : i + batch_size]
        results = await asyncio.gather(*(check_node(ip, p) for ip, p in batch))
        alive_nodes.extend([r for r in results if r])

    log(f"[*] [{name}] 潜在源总数: {len(alive_nodes)}")

    success_count = 0
    for node in alive_nodes:
        if await verify_stream(session, node, test_udp):
            if save_to_repo(name, node):
                log(f"  ✅ [{name}] 成功添加: {node}")
                success_count += 1
    log(f"[*] [{name}] 扫描结束，新增: {success_count} 个")

def save_to_repo(filename, node):
    target_file = f"{filename}.txt"
    existing = set()
    if os.path.exists(target_file):
        with open(target_file, 'r', encoding='utf-8') as f:
            existing = {line.strip() for line in f if line.strip() and not line.startswith('#')}
    
    if node not in existing:
        with open(target_file, 'a', encoding='utf-8') as f:
            if not existing: f.write(f"# {filename}\n")
            f.write(f"{node}\n")
        return True
    return False

async def main():
    if not os.path.exists(CONFIG_PATH): return
    with open(CONFIG_PATH, 'r', encoding='utf-8') as f:
        config = json.load(f)
    
    tasks = config if isinstance(config, list) else [config]
    
    # 模拟真实浏览器/播放器头，防止被运营商 WAF 拦截
    headers = {
        "User-Agent": "VLC/3.0.18 LibVLC/3.0.18",
        "Accept": "*/*"
    }
    
    async with aiohttp.ClientSession(headers=headers) as session:
        for t in tasks:
            name = t.get('name')
            test_udp = t.get('test_udp')
            # 自动取 prefer_region，没有则用 name
            region = t.get('prefer_region') or name
            if name and test_udp:
                await run_scan(session, name, test_udp, region)

if __name__ == "__main__":
    asyncio.run(main())
