import asyncio
import aiohttp

# --- 配置区域 ---
IP_FILE = 'ip.txt'          # 你的 IP 列表文件
RESULT_FILE = 'success.txt' # 存放扫出来的“宝藏”
PORTS = [1080, 8080, 3128, 7890, 10808] # 你想测试的端口
TIMEOUT = 5                 # 超时设置（建议稍微长一点，提高准确率）
CONCURRENCY = 30            # 并发数

async def check_proxy(ip, port, session):
    proxy_url = f"http://{ip}:{port}"
    test_url = "http://httpbin.org" # 验证地址
    
    try:
        # 尝试匿名访问
        async with session.get(test_url, proxy=proxy_url, timeout=TIMEOUT) as resp:
            if resp.status == 200:
                result = f"[+] 发现可用代理: {ip}:{port}"
                print(result)
                with open(RESULT_FILE, "a") as f:
                    f.write(f"{ip}:{port}\n")
                return True
    except aiohttp.ClientResponseError as e:
        if e.status == 407:
            print(f"[-] 有锁 (407): {ip}:{port}")
    except:
        # 其他连接错误（端口未开、超时等）直接忽略
        pass
    return False

async def worker(queue, session):
    while not queue.empty():
        ip, port = await queue.get()
        await check_proxy(ip, port, session)
        queue.task_done()

async def main():
    # 1. 读取 IP 文件
    try:
        with open(IP_FILE, 'r') as f:
            ips = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"错误: 找不到 {IP_FILE}")
        return

    queue = asyncio.Queue()
    for ip in ips:
        for port in PORTS:
            await queue.put((ip, port))

    print(f"开始扫描 {len(ips)} 个 IP，共 {queue.qsize()} 个任务...")

    # 2. 启动异步请求
    async with aiohttp.ClientSession() as session:
        tasks = []
        for _ in range(CONCURRENCY):
            tasks.append(asyncio.create_task(worker(queue, session)))
        await asyncio.gather(*tasks)

    print(f"\n扫描完成！结果已存入 {RESULT_FILE}")

if __name__ == "__main__":
    asyncio.run(main())
