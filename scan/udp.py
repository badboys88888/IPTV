import asyncio
import aiohttp
import json
import os
import ipaddress

# === 核心配置 ===
CONFIG_PATH = 'config.json'   # JSON配置文件路径
INPUT_IP = 'scan/udp.txt'      # 扫描号段文件
SCAN_CONCURRENCY = 2000       # 端口探测并发
IPTV_PORTS = [4000, 4022, 8000, 8080, 8888, 9000, 9999] # 组播常用端口

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
    # 尝试两种常见的路径格式
    for path in ["udp", "rtp"]:
        url = f"http://{node}/{path}/{test_udp}"
        try:
            async with session.get(url, timeout=5) as r:
                # 关键：检查 Content-Type
                # 如果返回的是 application/json，说明是报错信息，直接跳过
                ctype = r.headers.get('Content-Type', '').lower()
                if "json" in ctype:
                    continue 
                
                if r.status == 200:
                    # 尝试读取数据，验证是否为二进制流（视频）
                    content = await r.content.read(1024 * 100) # 100KB
                    if len(content) > 5000: # 确保收到了足够的数据量
                        return True
        except:
            continue
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

# 注意：函数参数增加了 prefer_region
async def run_scan(session, name, test_udp, prefer_region):
    """
    通过 prefer_region 匹配 udp.txt 中的 # 标签
    """
    if not os.path.exists(INPUT_IP):
        print(f"❌ 找不到文件: {INPUT_IP}")
        return

    all_ips = []
    is_target_region = False
    
    with open(INPUT_IP, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line: continue
            
            if line.startswith('#'):
                # 核心改动：用 prefer_region 来匹配注释行
                # 例如 prefer_region 是 "辽宁"，那么 # 辽宁电信 就能匹配上
                if prefer_region and prefer_region in line:
                    is_target_region = True
                else:
                    is_target_region = False
                continue
            
            if is_target_region:
                try:
                    net = ipaddress.IPv4Network(line, strict=False)
                    all_ips.extend([str(ip) for ip in list(net)])
                except: continue

    # ... 后续探测逻辑不变 ...


    if not all_ips:
        print(f"[-] [{name}] 在 {INPUT_IP} 中未发现匹配网段，跳过")
        return

    print(f"[*] [{name}] 任务启动，探测点位: {len(all_ips) * len(IPTV_PORTS)} 个...")
    
    # 2. 端口快扫阶段
    alive_nodes = []
    sem = asyncio.Semaphore(SCAN_CONCURRENCY)

    async def scan_worker(ip, port):
        async with sem:
            res = await port_scanner(ip, port)
            if res:
                alive_nodes.append(res)

    scan_tasks = [scan_worker(ip, p) for ip in all_ips for p in IPTV_PORTS]
    await asyncio.gather(*scan_tasks)
    print(f"[*] [{name}] 开放端口点位: {len(alive_nodes)} 个")

    # 3. 拉流验证阶段 (核心：利用你写的 verify_stream 过滤 JSON)
    count = 0
    for node in alive_nodes:
        # 这里会调用你写的包含 Content-Type 检查的 verify_stream
        if await verify_stream(session, node, test_udp):
            if save_to_repo(name, node):
                print(f"✅ [{name}] 新增有效源: {node}")
                count += 1
            else:
                print(f"➖ [{name}] 已存在: {node}")
    
    print(f"[*] [{name}] 扫描结束，本次新增: {count} 个")

    
    # --- 后续的端口快扫和 verify_stream 逻辑保持不变 ---

async def main():
    # ... 加载 config_data 代码 ...

    async with aiohttp.ClientSession() as session:
        for task in tasks:
            name = task.get('name', '默认分类')
            test_udp = task.get('test_udp')
            # 获取 prefer_region 字段
            prefer_region = task.get('prefer_region') 
            
            if not test_udp:
                continue
            
            # 传四个参数给 run_scan
            await run_scan(session, name, test_udp, prefer_region)

if __name__ == "__main__":
    asyncio.run(main())
