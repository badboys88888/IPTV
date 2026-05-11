import asyncio
import os
import aiohttp
import ipaddress
from aiohttp_socks import ProxyConnector

# --- 配置区域 ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
IP_FILE = os.path.join(BASE_DIR, 'ip.txt')
RESULT_FILE = os.path.join(BASE_DIR, 'success.txt')

# 如果 ip.txt 里没写端口，脚本会尝试扫描以下端口
PORTS = [1080, 1081, 8080, 3128, 7890] 
TIMEOUT = 5
CONCURRENCY = 50  # 并发数

async def verify_proxy(ip, port):
    """验证 Socks5 代理是否可用"""
    proxy_url = f'socks5://{ip}:{port}'
    connector = ProxyConnector.from_url(proxy_url)
    
    try:
        # 使用 socks5 协议进行验证
        async with aiohttp.ClientSession(connector=connector) as session:
            # 访问 httpbin 验证 IP 出口
            async with session.get("http://httpbin.org", timeout=TIMEOUT) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    print(f"[+] 成功! {ip}:{port} | 出口IP: {data.get('origin')}")
                    return f"{ip}:{port}"
    except Exception:
        # 验证失败直接跳过
        pass
    return None

async def worker(queue, results):
    """并发执行者"""
    while not queue.empty():
        ip, port = await queue.get()
        res = await verify_proxy(ip, port)
        if res:
            results.append(res)
        queue.task_done()

async def main():
    if not os.path.exists(IP_FILE):
        print(f"错误: 找不到输入文件 {IP_FILE}")
        return

    tasks_list = []
    
    # 解析 ip.txt
    with open(IP_FILE, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            try:
                # 1. 处理网段格式 (如 218.255.83.218/28)
                if '/' in line:
                    net = ipaddress.ip_network(line, strict=False)
                    for ip in net:
                        for p in PORTS:
                            tasks_list.append((str(ip), p))
                
                # 2. 处理自带端口格式 (如 218.255.83.218:1080)
                elif ':' in line:
                    parts = line.split(':')
                    ip_val = parts[0].strip()
                    port_val = int(parts[1].strip())
                    tasks_list.append((ip_val, port_val))
                
                # 3. 处理纯 IP 格式
                else:
                    for p in PORTS:
                        tasks_list.append((line, p))
            except Exception as e:
                print(f"跳过非法行 [{line}]: {e}")

    if not tasks_list:
        print("未发现有效扫描任务。")
        return

    queue = asyncio.Queue()
    for task in tasks_list:
        await queue.put(task)

    results = []
    print(f"解析完成: 共有 {len(tasks_list)} 个检测任务。并发数: {CONCURRENCY}")
    
    # 启动异步 Worker
    workers = [asyncio.create_task(worker(queue, results)) for _ in range(CONCURRENCY)]
    await asyncio.gather(*workers)

    # 汇总结果
    if results:
        # 确保结果去重
        unique_results = sorted(list(set(results)))
        with open(RESULT_FILE, 'a', encoding='utf-8') as f:
            for r in unique_results:
                f.write(r + '\n')
        print(f"\n[!] 检测结束: 发现 {len(unique_results)} 个可用节点，已存入 {RESULT_FILE}")
    else:
        print("\n[?] 检测结束: 未发现可用节点。")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
