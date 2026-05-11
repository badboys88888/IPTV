import asyncio
import os
import aiohttp
import ipaddress
from aiohttp_socks import ProxyConnector

# --- 配置区域 ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
IP_FILE = os.path.join(BASE_DIR, 'ip.txt')
RESULT_FILE = os.path.join(BASE_DIR, 'success.txt')

# 默认探测端口
# 如果 ip.txt 没写端口，则尝试这些
DEFAULT_PORTS = [1080, 1081, 8080, 3128, 443] 
TIMEOUT = 5
CONCURRENCY = 30 # 在 GitHub 上运行，并发建议保守一点

async def verify_proxy(ip, port):
    """检测是否为无密码的可用 Socks5 代理"""
    proxy_url = f'socks5://{ip}:{port}'
    connector = ProxyConnector.from_url(proxy_url)
    
    try:
        async with aiohttp.ClientSession(connector=connector) as session:
            # 访问 httpbin 验证真实出口 IP
            async with session.get("http://httpbin.org", timeout=TIMEOUT) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    print(f"[+] 发现节点! {ip}:{port} | 出口: {data.get('origin')}")
                    return f"{ip}:{port}"
    except Exception:
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
    # 确保成功文件存在，防止 Git 报错
    if not os.path.exists(RESULT_FILE):
        open(RESULT_FILE, 'a').close()

    if not os.path.exists(IP_FILE):
        print(f"找不到输入文件: {IP_FILE}")
        return

    tasks_list = []
    
    # 1. 解析 IP / 网段 / IP:端口
    with open(IP_FILE, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'): continue
            
            try:
                if '/' in line: # 处理 CIDR 如 218.255.83.218/28
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
                print(f"解析错误 [{line}]: {e}")

    if not tasks_list:
        print("任务列表为空。")
        return

    # 2. 开始异步扫描
    queue = asyncio.Queue()
    for task in tasks_list:
        await queue.put(task)

    results = []
    print(f"开始检测 {len(tasks_list)} 个目标...")
    
    workers = [asyncio.create_task(worker(queue, results)) for _ in range(CONCURRENCY)]
    await asyncio.gather(*workers)

    # 3. 保存结果
    if results:
        unique_results = sorted(list(set(results)))
        with open(RESULT_FILE, 'a', encoding='utf-8') as f:
            for r in unique_results:
                f.write(r + '\n')
        print(f"\n[!] 完成! 发现 {len(unique_results)} 个新节点。")
    else:
        print("\n[?] 完成，本次未发现可用节点。")

if __name__ == "__main__":
    asyncio.run(main())
