import asyncio
import ipaddress
import os
import random

# === 配置区 ===
TARGET_PORTS = [443, 8443, 8080, 2053, 2083, 2096, 10076, 12755]
CONCURRENCY = 1000  # GitHub Actions 性能强，可以开到 1000
MAX_IPS_PER_NET = 512  # 每个网段最多随机抽取的 IP 数量，防止死磕大网段
TIMEOUT = 1.5       # 超时时间

async def scan_port(ip, port):
    try:
        conn = asyncio.open_connection(str(ip), port)
        reader, writer = await asyncio.wait_for(conn, timeout=TIMEOUT)
        writer.close()
        await writer.wait_closed()
        return f"{ip}:{port}"
    except:
        return None

async def worker(queue, results):
    while True:
        task = await queue.get()
        if task is None: break
        ip, port = task
        res = await scan_port(ip, port)
        if res:
            print(f"[+] 发现存活: {res}")
            results.append(res)
        queue.task_done()

async def main():
    # 路径对齐：确保在 GitHub Actions 环境下能读到 scan 文件夹下的文件
    input_path = "scan/ip.txt"
    output_path = "scan/results.txt"
    
    if not os.path.exists(input_path):
        print(f"[!] 找不到文件: {input_path}")
        return
    
    all_tasks = []
    with open(input_path, "r") as f:
        for line in f:
            net_str = line.strip()
            if not net_str: continue
            try:
                network = ipaddress.IPv4Network(net_str, strict=False)
                # 如果网段太大，随机抽样；如果网段小，全量扫
                ips = list(network)
                if len(ips) > MAX_IPS_PER_NET:
                    ips = random.sample(ips, MAX_IPS_PER_NET)
                
                for ip in ips:
                    for port in TARGET_PORTS:
                        all_tasks.append((ip, port))
            except Exception as e:
                print(f"解析网段 {net_str} 出错: {e}")

    # 打乱所有任务的顺序，实现全球/全网段随机跳跃扫描
    random.shuffle(all_tasks)
    print(f"[*] 任务加载完成，准备探测 {len(all_tasks)} 个点...")

    queue = asyncio.Queue()
    results = []
    
    # 启动工作协程
    workers = [asyncio.create_task(worker(queue, results)) for _ in range(CONCURRENCY)]

    for task in all_tasks:
        await queue.put(task)

    # 放入停止信号
    for _ in range(CONCURRENCY):
        await queue.put(None)

    await asyncio.gather(*workers)

    # 保存结果
    with open(output_path, "w") as f:
        for r in results:
            f.write(r + "\n")
    
    print(f"[*] 扫描结束，共发现 {len(results)} 个节点。")

if __name__ == "__main__":
    asyncio.run(main())
