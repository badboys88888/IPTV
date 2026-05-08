import asyncio
import ipaddress
import os

# 配置要扫的网段和端口
TARGET_PORTS = [443, 8443, 2053, 2083, 2096, 8080]
CONCURRENCY = 800  # GitHub 的带宽很大，并发可以高一点

async def scan_port(ip, port):
    try:
        conn = asyncio.open_connection(str(ip), port)
        reader, writer = await asyncio.wait_for(conn, timeout=1.5)
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
            results.append(res)
        queue.task_done()

async def main():
    if not os.path.exists('scan/ip.txt'): return
    
    tasks = []
    with open("scan/ip.txt", "r") as f:
        for line in f:
            net = line.strip()
            if not net: continue
            for ip in ipaddress.IPv4Network(net, strict=False):
                for port in TARGET_PORTS:
                    tasks.append((ip, port))

    queue = asyncio.Queue()
    results = []
    workers = [asyncio.create_task(worker(queue, results)) for _ in range(CONCURRENCY)]

    for task in tasks: await queue.put(task)
    for _ in range(CONCURRENCY): await queue.put(None)

    await asyncio.gather(*workers)

    with open("results.txt", "w") as f:
        for r in results: f.write(r + "\n")

if __name__ == "__main__":
    asyncio.run(main())
