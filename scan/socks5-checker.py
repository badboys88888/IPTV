import asyncio
import os
import aiohttp
import ipaddress
from aiohttp_socks import ProxyConnector

# --- 配置 ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
IP_FILE = os.path.join(BASE_DIR, 'ip.txt')
RESULT_FILE = os.path.join(BASE_DIR, 'success.txt')

# 你确定端口是 1080，我们重点扫它
DEFAULT_PORTS = [1080] 
TIMEOUT = 12  # 进一步增加超时时间
CONCURRENCY = 20 # 降低并发，防止被 Hetzner 封锁 GitHub IP

async def verify_proxy(ip, port):
    """极致兼容性验证"""
    test_urls = [
        "http://cloudflare.com",
        "http://httpbin.org",
        "http://google.com"
    ]
    
    # 1. 尝试 Socks5
    for url in test_urls:
        try:
            connector = ProxyConnector.from_url(f'socks5://{ip}:{port}')
            async with aiohttp.ClientSession(connector=connector) as session:
                async with session.get(url, timeout=TIMEOUT) as resp:
                    if resp.status in [200, 204]:
                        print(f"[找到Socks5] {ip}:{port}")
                        return f"socks5://{ip}:{port}"
        except Exception:
            continue # 换个地址再试

    # 2. 尝试 HTTP
    for url in test_urls:
        try:
            async with aiohttp.ClientSession() as session:
                proxy_url = f"http://{ip}:{port}"
                async with session.get(url, proxy=proxy_url, timeout=TIMEOUT) as resp:
                    if resp.status in [200, 204]:
                        print(f"[找到HTTP] {ip}:{port}")
                        return f"http://{ip}:{port}"
        except Exception:
            continue
    
    return None

async def worker(queue, results):
    while not queue.empty():
        ip, port = await queue.get()
        res = await verify_proxy(ip, port)
        if res:
            results.append(res)
        queue.task_done()
        # 每次检测完微调休息，避免被封
        await asyncio.sleep(0.1)

async def main():
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
                if '/' in line:
                    net = ipaddress.ip_network(line, strict=False)
                    for ip in net:
                        for p in DEFAULT_PORTS:
                            tasks_list.append((str(ip), p))
                elif ':' in line:
                    parts = line.split(':')
                    tasks_list.append((parts[0].strip(), int(parts[1].strip())))
                else:
                    for p in DEFAULT_PORTS:
                        tasks_list.append((line, p))
            except Exception as e:
                print(f"Parsing error: {line} -> {e}")

    if not tasks_list:
        print("No tasks.")
        return

    queue = asyncio.Queue()
    for task in tasks_list:
        await queue.put(task)

    results = []
    print(f"开始深度检测 {len(tasks_list)} 个目标...")
    
    workers = [asyncio.create_task(worker(queue, results)) for _ in range(CONCURRENCY)]
    await asyncio.gather(*workers)

    if results:
        # 去重并合并
        old_results = set()
        if os.path.exists(RESULT_FILE):
            with open(RESULT_FILE, 'r') as f:
                old_results = set(line.strip() for line in f if line.strip())
        
        final_results = sorted(list(old_results.union(set(results))))
        with open(RESULT_FILE, 'w', encoding='utf-8') as f:
            for r in final_results:
                f.write(r + '\n')
        print(f"检测结束，当前共保存 {len(final_results)} 个节点。")
    else:
        print("检测结束，未发现可用节点。请检查目标是否需要密码或防火墙是否拦截。")

if __name__ == "__main__":
    asyncio.run(main())
