import asyncio
import os
import aiohttp
import ipaddress
from aiohttp_socks import ProxyConnector

# --- 配置 ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
IP_FILE = os.path.join(BASE_DIR, 'ip.txt')
RESULT_FILE = os.path.join(BASE_DIR, 'success.txt')

# 默认扫描端口 (你可以继续增加)
DEFAULT_PORTS = [80, 443, 1080, 1081, 3128, 8080, 8888, 7890]
TIMEOUT = 10  # 增加到10秒，应对德国到GitHub的延迟
CONCURRENCY = 50 # 并发数

async def verify_proxy(ip, port):
    """同时检测 Socks5 和 HTTP 协议"""
    test_url = "http://cloudflare.com"
    
    # 1. 尝试 Socks5
    try:
        connector = ProxyConnector.from_url(f'socks5://{ip}:{port}')
        async with aiohttp.ClientSession(connector=connector) as session:
            async with session.get(test_url, timeout=TIMEOUT) as resp:
                if resp.status == 200:
                    print(f"[找到Socks5] {ip}:{port}")
                    return f"socks5://{ip}:{port}"
    except:
        pass

    # 2. 尝试 HTTP
    try:
        async with aiohttp.ClientSession() as session:
            proxy_url = f"http://{ip}:{port}"
            async with session.get(test_url, proxy=proxy_url, timeout=TIMEOUT) as resp:
                if resp.status == 200:
                    print(f"[找到HTTP] {ip}:{port}")
                    return f"http://{ip}:{port}"
    except:
        pass
    
    return None

async def worker(queue, results):
    while not queue.empty():
        ip, port = await queue.get()
        res = await verify_proxy(ip, port)
        if res:
            results.append(res)
        queue.task_done()

async def main():
    # 确保输出文件存在
    if not os.path.exists(RESULT_FILE):
        open(RESULT_FILE, 'a').close()

    if not os.path.exists(IP_FILE):
        print(f"Error: {IP_FILE} not found")
        return

    tasks_list = []
    with open(IP_FILE, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'): continue
            try:
                if '/' in line: # 处理网段 176.9.62.93/24
                    net = ipaddress.ip_network(line, strict=False)
                    for ip in net:
                        for p in DEFAULT_PORTS:
                            tasks_list.append((str(ip), p))
                elif ':' in line: # 处理 IP:PORT
                    parts = line.split(':')
                    tasks_list.append((parts[0].strip(), int(parts[1].strip())))
                else: # 纯 IP
                    for p in DEFAULT_PORTS:
                        tasks_list.append((line, p))
            except Exception as e:
                print(f"Parsing error: {line} -> {e}")

    if not tasks_list:
        print("No tasks found.")
        return

    queue = asyncio.Queue()
    for task in tasks_list:
        await queue.put(task)

    results = []
    print(f"开始检测 {len(tasks_list)} 个目标任务...")
    
    workers = [asyncio.create_task(worker(queue, results)) for _ in range(CONCURRENCY)]
    await asyncio.gather(*workers)

    if results:
        # 读取旧结果进行去重
        old_results = set()
        if os.path.exists(RESULT_FILE):
            with open(RESULT_FILE, 'r') as f:
                old_results = set(line.strip() for line in f if line.strip())
        
        new_results = set(results)
        final_results = sorted(list(old_results.union(new_results)))

        with open(RESULT_FILE, 'w', encoding='utf-8') as f:
            for r in final_results:
                f.write(r + '\n')
        print(f"检测结束，当前共有 {len(final_results)} 个可用节点已保存。")
    else:
        print("检测结束，未发现可用节点。")

if __name__ == "__main__":
    asyncio.run(main())
