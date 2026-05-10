import asyncio
import aiohttp
import json
import os
import ipaddress

# === 核心配置 ===
CONFIG_PATH = 'config.json'   # JSON配置文件路径
INPUT_IP = 'scan/udp.txt'      # 扫描号段文件
SCAN_CONCURRENCY = 1024       # 并发数（GitHub Actions建议1024，本地可2000）
IPTV_PORTS = [4000, 4022, 8000, 8080, 8888, 9000, 9999] # 组播常用端口

async def verify_stream(session, node, test_udp):
    """第二阶段：拉流深度验证（排除假源和JSON报错）"""
    # 尝试 udp 和 rtp 两种路径
    for path in ["udp", "rtp"]:
        url = f"http://{node}/{path}/{test_udp}"
        try:
            async with session.get(url, timeout=5) as r:
                # 1. 检查内容类型，如果是json或文本，说明是报错信息
                ctype = r.headers.get('Content-Type', '').lower()
                if "json" in ctype or "text" in ctype or "html" in ctype:
                    continue
                
                if r.status == 200:
                    # 2. 读取 128KB 数据验证真实性
                    content = await r.content.read(128 * 1024)
                    if len(content) > 10000: # 收到超过10KB数据判定为真流
                        return True
        except:
            continue
    return False

def save_to_repo(filename, node):
    """追加保存到 TXT，并自动去重"""
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
        print(f"❌ 找不到网段文件: {INPUT_IP}")
        return

    # 1. 提取匹配 prefer_region 的 IP 网段
    all_ips = []
    is_target_region = False
    with open(INPUT_IP, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line: continue
            if line.startswith('#'):
                # 只要 prefer_region (如"宁夏") 包含在注释行里，就开始收集
                is_target_region = (prefer_region and prefer_region in line)
                continue
            if is_target_region:
                try:
                    net = ipaddress.IPv4Network(line, strict=False)
                    all_ips.extend([str(ip) for ip in list(net)])
                except: continue

    if not all_ips:
        print(f"[-] [{name}] 在 {INPUT_IP} 中未匹配到 [{prefer_region}] 标签，跳过")
        return

    print(f"[*] [{name}] 启动，探测点位: {len(all_ips) * len(IPTV_PORTS)}")
    
    # 2. 第一阶段：扫端口并识别 /status (过滤 JSON 报错)
    alive_nodes = []
    sem = asyncio.Semaphore(SCAN_CONCURRENCY)

    async def check_node(ip, port):
        async with sem:
            node = f"{ip}:{port}"
            try:
                # 优先访问 status 页面，看是不是真正的 udpxy
                async with session.get(f"http://{node}/status", timeout=1.5) as r:
                    if r.status == 200:
                        text = await r.text()
                        # 必须包含 udpxy 且不含那个报错 JSON 的特征码
                        if "udpxy" in text.lower() and "108545" not in text:
                            return node
            except: pass
            return None

    # 分批执行，防止内存溢出
    all_params = [(ip, p) for ip in all_ips for p in IPTV_PORTS]
    batch_size = 5000
    for i in range(0, len(all_params), batch_size):
        batch = all_params[i : i + batch_size]
        results = await asyncio.gather(*(check_node(ip, p) for ip, p in batch))
        alive_nodes.extend([r for r in results if r])
        print(f"[*] [{name}] 探测进度: {i + len(batch)} / {len(all_params)}")

    print(f"[*] [{name}] 发现潜在真源点位: {len(alive_nodes)} 个")

    # 3. 第二阶段：精准拉流验证 (只针对该地区的 test_udp)
    count = 0
    for node in alive_nodes:
        if await verify_stream(session, node, test_udp):
            if save_to_repo(name, node):
                print(f"✅ [{name}] 新增有效源: {node}")
                count += 1
    print(f"[*] [{name}] 任务结束，本次新增: {count} 个")

async def main():
    if not os.path.exists(CONFIG_PATH):
        print(f"❌ 找不到 {CONFIG_PATH}")
        return

    with open(CONFIG_PATH, 'r', encoding='utf-8') as f:
        config_data = json.load(f)

    # 兼容 JSON 是单个对象或列表的情况
    if isinstance(config_data, list):
        tasks = config_data
    elif isinstance(config_data, dict):
        tasks = config_data.get('tasks', [config_data])
    else:
        tasks = []

    async with aiohttp.ClientSession() as session:
        for task in tasks:
            name = task.get('name', '默认分类')
            test_udp = task.get('test_udp')
            # 优先使用 prefer_region 匹配，没有则尝试用 name
            region = task.get('prefer_region') or name
            
            if not test_udp:
                continue
            
            await run_scan(session, name, test_udp, region)

if __name__ == "__main__":
    asyncio.run(main())
