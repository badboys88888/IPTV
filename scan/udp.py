import asyncio
import aiohttp
import json
import os
import ipaddress

# === 核心配置 ===
CONFIG_PATH = 'config.json'   # JSON配置文件路径
INPUT_IP = 'scan/ip.txt'      # 扫描号段文件
SCAN_CONCURRENCY = 2000       # 端口探测并发
IPTV_PORTS = [4022, 8000, 8080, 8888, 9000] # 组播常用端口

async def port_scanner(ip, port):
    """第一阶段：快速探测 TCP 端口"""
    try:
        conn = asyncio.open_connection(str(ip), port)
        _, writer = await asyncio.wait_for(conn, timeout=0.8)
        writer.close()
        await writer.wait_closed()
        return f"{ip}:{port}"
    except:
        return None

async def verify_stream(session, node, test_udp):
    """第二阶段：拉流深度验证（根据 JSON 里的 test_udp）"""
    # 构造 udpxy 路径
    url = f"http://{node}/udp/{test_udp}"
    try:
        async with session.get(url, timeout=5) as r:
            if r.status == 200:
                # 尝试读取 256KB 数据验证真实性
                content = await r.content.read(256 * 1024)
                if len(content) > 0:
                    return True
    except:
        pass
    return False

def save_to_repo(filename, node):
    """追加保存到 TXT，并自动去重"""
    target_file = f"{filename}.txt"
    existing = set()
    
    # 1. 检查已有的 IP 记录
    if os.path.exists(target_file):
        with open(target_file, 'r', encoding='utf-8') as f:
            # 过滤掉注释行和空行
            existing = {line.strip() for line in f if line.strip() and not line.startswith('#')}
    
    # 2. 如果是新 IP，则追加
    if node not in existing:
        with open(target_file, 'a', encoding='utf-8') as f:
            if not existing:
                f.write(f"# {filename}\n")
            f.write(f"{node}\n")
        return True
    return False

async def run_scan(session, name, test_udp):
    """执行具体的扫描逻辑"""
    if not os.path.exists(INPUT_IP):
        print(f"❌ 找不到网段文件: {INPUT_IP}")
        return

    # 解析 ip.txt 中的网段
    all_ips = []
    with open(INPUT_IP, 'r') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'): continue
            try:
                net = ipaddress.IPv4Network(line, strict=False)
                all_ips.extend([str(ip) for ip in list(net)])
            except: continue

    print(f"[*] [{name}] 任务启动，探测点位: {len(all_ips) * len(IPTV_PORTS)} 个...")
    
    # 1. 端口快扫
    alive_nodes = []
    sem = asyncio.Semaphore(SCAN_CONCURRENCY)
    async def scan_worker(ip, port):
        async with sem:
            res = await port_scanner(ip, port)
            if res: alive_nodes.append(res)

    scan_tasks = [scan_worker(ip, p) for ip in all_ips for p in IPTV_PORTS]
    await asyncio.gather(*scan_tasks)
    print(f"[*] 开放端口点位: {len(alive_nodes)} 个")

    # 2. 拉流验证并分类追加
    count = 0
    for node in alive_nodes:
        if await verify_stream(session, node, test_udp):
            if save_to_repo(name, node):
                print(f"✅ [{name}] 新增有效源: {node}")
                count += 1
            else:
                print(f"➖ [{name}] 已存在: {node}")
    print(f"[*] [{name}] 扫描结束，本次新增: {count} 个")

async def main():
    # 1. 加载 config.json
    if not os.path.exists(CONFIG_PATH):
        print(f"❌ 根目录下找不到 {CONFIG_PATH}")
        return

    with open(CONFIG_PATH, 'r', encoding='utf-8') as f:
        config_data = json.load(f)

    # 兼容 JSON 是单个对象或列表的情况
    tasks = config_data if isinstance(config_data, list) else [config_data]

    async with aiohttp.ClientSession() as session:
        for task in tasks:
            name = task.get('name', '默认分类')
            test_udp = task.get('test_udp')
            if not test_udp:
                print(f"⚠️ 任务 [{name}] 缺少 test_udp，跳过")
                continue
            
            await run_scan(session, name, test_udp)

if __name__ == "__main__":
    asyncio.run(main())
