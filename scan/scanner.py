import asyncio
import aiohttp
import ipaddress
import random
import os

# === 配置区 ===
INPUT = 'proxyip/ip.txt'
OUTPUT = 'proxyip/useful_proxies.txt'
SCAN_CONCURRENCY = 1000   # 第一阶段端口探测并发
CHECK_CONCURRENCY = 50    # 第二阶段接口检测并发（建议不要太高，保护Worker）
TARGET_PORTS = [443, 8443, 2053, 2083, 2096, 8080] # CF支持的端口
MAX_IPS_PER_NET = 2000    # 每个网段抽取的样数
# 确保接口地址后面跟着 ?proxyip={}
CHECK_URL = 'https://dawn-lab-5568.177866120.workers.dev/check?proxyip={}'

async def port_scanner(ip, port):
    """第一阶段：快速探测端口存活"""
    try:
        # 使用 asyncio 快速建立 TCP 连接
        conn = asyncio.open_connection(str(ip), port)
        _, writer = await asyncio.wait_for(conn, timeout=1.5)
        writer.close()
        await writer.wait_closed()
        return f"{ip}:{port}"
    except:
        return None

async def check_via_interface(session, proxy_addr, sem):
    """第二阶段：将探测存活的 IP:PORT 填入你的接口进行精测"""
    async with sem:
        # 这里会将 proxy_addr (例如 1.1.1.1:443) 填入 CHECK_URL 的 {} 中
        full_url = CHECK_URL.format(proxy_addr)
        try:
            async with session.get(full_url, timeout=15) as r:
                if r.status == 200:
                    data = await r.json()
                    # 只有接口明确返回 success 为 True 才是我们要的
                    if data.get('success') is True:
                        print(f"🔥 [成功] {proxy_addr} | colo: {data.get('colo')} | 延迟: {data.get('responseTime')}ms")
                        return proxy_addr
        except Exception as e:
            # print(f"检测出错 {proxy_addr}: {e}") # 调试时可以打开
            pass
    return None

async def main():
    # 1. 自动拆解 ip.txt 里的网段并随机抽样
    all_tasks = []
    if not os.path.exists(INPUT):
        print(f"找不到输入文件: {INPUT}")
        return

    with open(INPUT, 'r') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'): continue
            try:
                net = ipaddress.IPv4Network(line, strict=False)
                ips = list(net)
                if len(ips) > MAX_IPS_PER_NET:
                    ips = random.sample(ips, MAX_IPS_PER_NET)
                for ip in ips:
                    for port in TARGET_PORTS:
                        all_tasks.append((ip, port))
            except: continue
    
    random.shuffle(all_tasks)
    print(f"[*] 第一阶段：开始在全球/全网段探测 {len(all_tasks)} 个点位...")

    # 2. 执行并发端口探测
    alive_nodes = []
    sem_scan = asyncio.Semaphore(SCAN_CONCURRENCY)
    async def scan_task(ip, port):
        async with sem_scan:
            res = await port_scanner(ip, port)
            if res: alive_nodes.append(res)

    await asyncio.gather(*(scan_task(ip, port) for ip, port in all_tasks))
    print(f"[*] 探测结束，开放端口的 IP 数量: {len(alive_nodes)}")

    if not alive_nodes:
        print("[!] 本次扫描未发现开放端口的 IP，请检查网段或端口配置。")
        return

    # 3. 对存活 IP 进行接口精测
    print(f"[*] 第二阶段：正在将存活 IP 喂给接口 {CHECK_URL.split('?')[0]} ...")
    sem_check = asyncio.Semaphore(CHECK_CONCURRENCY)
    
    # 建立持久会话提高效率
    async with aiohttp.ClientSession() as session:
        check_tasks = [check_via_interface(session, node, sem_check) for node in alive_nodes]
        final_results = await asyncio.gather(*check_tasks)

    # 4. 过滤并保存结果
    valid_list = [r for r in final_results if r]
    
    # 确保文件夹存在
    os.makedirs(os.path.dirname(OUTPUT), exist_ok=True)
    with open(OUTPUT, 'w') as f:
        for p in valid_list:
            f.write(p + '\n')
    
    print(f"\n[DONE] 筛选完成！共有 {len(valid_list)} 个 IP 通过了接口测试。")
    print(f"结果已存入: {OUTPUT}")

if __name__ == "__main__":
    asyncio.run(main())
