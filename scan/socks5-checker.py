import asyncio
import os
import aiohttp
import ipaddress
from aiohttp_socks import ProxyConnector

# --- 配置区 ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
IP_FILE = os.path.join(BASE_DIR, 'ip.txt')
RESULT_FILE = os.path.join(BASE_DIR, 'success.txt')

# 扫描参数
DEFAULT_PORTS = [1080] 
TIMEOUT = 5            # 探测超时（秒）
CONCURRENCY = 1000     # 并发数（根据机器性能可调至 500-2000）
TEST_URLS = [
    "http://cloudflare.com",
    "http://httpbin.org"
]

# 并发信号量
sem = asyncio.Semaphore(CONCURRENCY)

async def check_port_opened(ip, port):
    """第一阶段：TCP端口探测。能瞬间排除掉 99% 的无效目标"""
    try:
        # 使用低级 API 快速尝试连接
        conn = asyncio.open_connection(ip, port)
        reader, writer = await asyncio.wait_for(conn, timeout=3)
        writer.close()
        await writer.wait_closed()
        return True
    except:
        return False

async def verify_proxy_protocol(ip, port):
    """第二阶段：深度协议验证（支持 Socks5 和 HTTP）"""
    # 1. 尝试 Socks5 验证
    for url in TEST_URLS:
        try:
            connector = ProxyConnector.from_url(f'socks5://{ip}:{port}')
            async with aiohttp.ClientSession(connector=connector) as session:
                async with session.get(url, timeout=TIMEOUT) as resp:
                    if resp.status in [200, 204]:
                        return f"socks5://{ip}:{port}"
        except:
            continue

    # 2. 尝试 HTTP 验证
    for url in TEST_URLS:
        try:
            async with aiohttp.ClientSession() as session:
                proxy_url = f"http://{ip}:{port}"
                async with session.get(url, proxy=proxy_url, timeout=TIMEOUT) as resp:
                    if resp.status in [200, 204]:
                        return f"http://{ip}:{port}"
        except:
            continue
            
    return None

async def bound_verify(ip, port, results):
    """带并发限制的任务执行器"""
    async with sem:
        # 第一步：端口没开直接跳过，不走后面的重型逻辑
        if await check_port_opened(ip, port):
            # 第二步：端口开了，再细测协议
            res = await verify_proxy_protocol(ip, port)
            if res:
                print(f"找到可用节点: {res}")
                results.append(res)

async def main():
    if not os.path.exists(IP_FILE):
        print(f"错误: 找不到输入文件 {IP_FILE}")
        return

    # 解析 IP 和网段
    all_tasks = []
    with open(IP_FILE, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'): continue
            try:
                if '/' in line: # 处理 CIDR 网段
                    net = ipaddress.ip_network(line, strict=False)
                    for ip in net:
                        for p in DEFAULT_PORTS:
                            all_tasks.append((str(ip), p))
                elif ':' in line: # 处理 IP:PORT 格式
                    parts = line.split(':')
                    all_tasks.append((parts[0].strip(), int(parts[1].strip())))
                else: # 处理 纯IP 格式
                    for p in DEFAULT_PORTS:
                        all_tasks.append((line, p))
            except Exception as e:
                print(f"解析跳过: {line} ({e})")

    total = len(all_tasks)
    print(f"任务加载完成: 共 {total} 个探测目标 | 并发: {CONCURRENCY}")
    
    results = []
    # 批量创建协程任务
    tasks = [asyncio.create_task(bound_verify(ip, p, results)) for ip, p in all_tasks]
    
    # 实时进度条逻辑
    async def show_progress():
        while True:
            done = len([t for t in tasks if t.done()])
            print(f"进度: [{done}/{total}] ({(done/total*100):.1f}%) | 发现: {len(results)}", end='\r')
            if done == total: break
            await asyncio.sleep(2)

    progress_task = asyncio.create_task(show_progress())
    
    # 等待所有扫描结束
    await asyncio.gather(*tasks)
    await progress_task # 确保进度显示完整

    # 结果去重保存
    if results:
        # 读取旧数据实现合并
        old_data = set()
        if os.path.exists(RESULT_FILE):
            with open(RESULT_FILE, 'r') as f:
                old_data = {l.strip() for l in f if l.strip()}
        
        final_list = sorted(list(old_data.union(set(results))))
        with open(RESULT_FILE, 'w', encoding='utf-8') as f:
            for item in final_list:
                f.write(item + '\n')
        print(f"\n\n扫描结束！新增 {len(results)} 个，当前总库共 {len(final_list)} 个节点。")
    else:
        print("\n\n扫描结束，未发现可用节点。")

if __name__ == "__main__":
    # Windows 环境下的并发兼容性修复
    if os.name == 'nt':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n用户手动停止。")
