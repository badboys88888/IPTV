import asyncio
import aiohttp
import ipaddress
import random
import os

# === 配置区 ===
# 确保在 GitHub Actions 根目录下运行时的相对路径正确
INPUT = 'scan/ip.txt'
OUTPUT = 'scan/useful_proxies.txt'

SCAN_CONCURRENCY = 1000   # 端口探测并发
CHECK_CONCURRENCY = 50    # 接口精测并发
# 常见的 Cloudflare 备用 HTTPS 端口
TARGET_PORTS = [443, 8443, 2053, 2083, 2087, 2093, 2096, 8080, 30001, 30006, 10443, 50001]
MAX_IPS_PER_NET = 10000    # 每个大网段随机抽取的样本数
CHECK_URL = 'https://dawn-lab-5568.177866120.workers.dev/check?proxyip={}'

async def port_scanner(ip, port):
    """第一阶段：快速探测 TCP 端口存活"""
    try:
        conn = asyncio.open_connection(str(ip), port)
        _, writer = await asyncio.wait_for(conn, timeout=1.5)
        writer.close()
        await writer.wait_closed()
        return f"{ip}:{port}"
    except:
        return None

async def check_via_interface(session, proxy_addr, sem):
    """第二阶段：将存活 IP 喂给接口精测"""
    async with sem:
        full_url = CHECK_URL.format(proxy_addr)
        try:
            async with session.get(full_url, timeout=15) as r:
                if r.status == 200:
                    data = await r.json()
                    if data.get('success') is True:
                        print(f"🔥 [成功] {proxy_addr} | colo: {data.get('colo')} | 响应: {data.get('responseTime')}ms")
                        return proxy_addr
        except:
            pass
    return None

async def main():
    if not os.path.exists(INPUT):
        print(f"[!] 找不到输入文件: {INPUT}")
        return

    # 1. 解析 ip.txt
    all_tasks = []
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
    print(f"[*] 第一阶段：开始探测 {len(all_tasks)} 个点位...")

    # 2. 端口快扫
    alive_nodes = []
    sem_scan = asyncio.Semaphore(SCAN_CONCURRENCY)
    async def scan_task(ip, port):
        async with sem_scan:
            res = await port_scanner(ip, port)
            if res: alive_nodes.append(res)

    await asyncio.gather(*(scan_task(ip, port) for ip, port in all_tasks))
    print(f"[*] 探测结束，开放端口的 IP 数量: {len(alive_nodes)}")

    if not alive_nodes:
        # 如果没扫到，创建一个空文件防止后续 git add 报错
        open(OUTPUT, 'w').close()
        print("[!] 未发现存活端口。")
        return

    # 3. 接口精测
    print(f"[*] 第二阶段：正在通过接口验证可用性...")
    sem_check = asyncio.Semaphore(CHECK_CONCURRENCY)
    async with aiohttp.ClientSession() as session:
        check_tasks = [check_via_interface(session, node, sem_check) for node in alive_nodes]
        final_results = await asyncio.gather(*check_tasks)

    # 4. 保存
    valid_list = [r for r in final_results if r]
    os.makedirs(os.path.dirname(OUTPUT), exist_ok=True)
    with open(OUTPUT, 'w') as f:
        for p in valid_list:
            f.write(p + '\n')
    
    print(f"\n[DONE] 最终筛选出 {len(valid_list)} 个可用 IP，已保存。")

if __name__ == "__main__":
    asyncio.run(main())
