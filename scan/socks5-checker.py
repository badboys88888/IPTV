import asyncio
import os
import aiohttp
from aiohttp_socks import ProxyConnector

# --- 配置 ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
IP_FILE = os.path.join(BASE_DIR, 'ip.txt')
RESULT_FILE = os.path.join(BASE_DIR, 'success.txt')
PORTS = [1080, 1081, 8080, 443]  # 如果ip.txt里带端口，这些会被忽略
TIMEOUT = 5
CONCURRENCY = 50

async def verify_proxy(ip, port):
    # 构造 Socks5 连接器
    proxy_url = f'socks5://{ip}:{port}'
    connector = ProxyConnector.from_url(proxy_url)
    
    try:
        # 使用 socks5 协议进行测试
        async with aiohttp.ClientSession(connector=connector) as session:
            async with session.get("http://httpbin.org", timeout=TIMEOUT) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    print(f"[+] 成功! {ip}:{port} | 出口IP: {data['origin']}")
                    return f"{ip}:{port}"
    except Exception:
        # 如果 Socks5 失败，这里可以扩展尝试 HTTP 协议，但 Socks5 是你的重点
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
    if not os.path.exists(IP_FILE):
        print(f"找不到文件: {IP_FILE}")
        return

    # 解析 ip.txt
    tasks_list = []
    with open(IP_FILE, 'r') as f:
        for line in f:
            line = line.strip()
            if not line: continue
            if ':' in line: # 如果自带端口 IP:PORT
                ip, port = line.split(':')
                tasks_list.append((ip, int(port)))
            else: # 只有 IP
                for p in PORTS:
                    tasks_list.append((line, p))

    queue = asyncio.Queue()
    for task in tasks_list:
        await queue.put(task)

    results = []
    print(f"开始检测 {len(tasks_list)} 个任务...")
    
    workers = [asyncio.create_task(worker(queue, results)) for _ in range(CONCURRENCY)]
    await asyncio.gather(*workers)

    # 写入结果
    if results:
        with open(RESULT_FILE, 'a') as f:
            for r in results:
                f.write(r + '\n')
        print(f"任务完成，发现 {len(results)} 个可用代理")
    else:
        print("扫描结束，未发现可用代理。")

if __name__ == "__main__":
    asyncio.run(main())
