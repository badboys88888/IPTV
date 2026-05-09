import asyncio
import aiohttp
import ipaddress
import random
import os
from collections import defaultdict

# === 配置区 ===
INPUT = 'scan/ip.txt'
OUTPUT = 'scan/useful_proxies.txt'

SCAN_CONCURRENCY = 5000
CHECK_CONCURRENCY = 50
GEO_CONCURRENCY = 20
TARGET_PORTS = [443, 8443, 2053, 2083, 2087, 2093, 2096, 8080, 30001, 30006, 10443, 50001, 20002, 12345, 8081]
MAX_IPS_PER_NET = 20000
CHECK_URL = 'https://dawn-lab-5568.177866120.workers.dev/check?proxyip={}'
GEO_API_URL = 'http://ip-api.com/json/{}?fields=status,country,countryCode,regionName,isp,as,query'

# 输出格式开关：True=显示地区，False=不显示地区
SHOW_REGION = True   # 改为 False 则格式变为 IP:PORT#编号-运营商类型

# 国家映射、运营商映射（与之前相同，此处省略节省篇幅，实际运行时请复制完整映射）
COUNTRY_MAP = { ... }  # 请复制前面的完整映射
ORG_MAP = { ... }      # 请复制前面的完整映射

# ========== 以下函数与之前相同，略作修改 ==========
async def port_scanner(ip, port):
    try:
        conn = asyncio.open_connection(str(ip), port)
        _, writer = await asyncio.wait_for(conn, timeout=1.5)
        writer.close()
        await writer.wait_closed()
        return f"{ip}:{port}"
    except:
        return None

async def check_via_interface(session, proxy_addr, sem):
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

async def fetch_geo_info(session, ip, sem):
    async with sem:
        url = GEO_API_URL.format(ip)
        try:
            async with session.get(url, timeout=8) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    if data.get('status') == 'success':
                        country_code = data.get('countryCode', '')
                        country_name = COUNTRY_MAP.get(country_code, data.get('country', '未知'))
                        region = data.get('regionName', '未知')
                        isp = data.get('isp', '')
                        as_info = data.get('as', '')
                        org_type = match_org(isp, as_info)
                        return {
                            'country': country_name,
                            'region': region,
                            'org_type': org_type,
                            'isp': isp,
                            'as': as_info
                        }
        except:
            pass
    return None

def match_org(isp, as_info):
    text = (isp + " " + as_info).lower()
    for key, val in ORG_MAP.items():
        if key in text:
            return val
    return isp[:20] if isp else "未知"

def format_proxy_output(valid_list, ip_geo_map):
    """根据 SHOW_REGION 开关格式化输出"""
    groups = defaultdict(list)
    for proxy in valid_list:
        ip = proxy.split(':')[0]
        geo = ip_geo_map.get(ip, {})
        country = geo.get('country', '未知')
        region = geo.get('region', '未知')
        org_type = geo.get('org_type', '未知')
        groups[country].append((proxy, region, org_type))

    output_lines = []
    for country in sorted(groups.keys()):
        output_lines.append(f"#{country}")
        proxies = groups[country]
        proxies.sort(key=lambda x: x[0])  # 按 IP:PORT 排序
        for idx, (proxy, region, org) in enumerate(proxies, start=1):
            number = f"{idx:03d}"
            if SHOW_REGION:
                # 格式: IP:PORT#地区-编号-运营商类型
                comment = f"{region}-{number}-{org}"
            else:
                # 格式: IP:PORT#编号-运营商类型
                comment = f"{number}-{org}"
            output_lines.append(f"{proxy}#{comment}")
    return output_lines

# ========== main 函数基本不变 ==========
async def main():
    if not os.path.exists(INPUT):
        print(f"[!] 找不到输入文件: {INPUT}")
        return

    # 解析 ip.txt 生成探测任务
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
            except:
                continue
    random.shuffle(all_tasks)
    print(f"[*] 第一阶段：开始探测 {len(all_tasks)} 个点位...")

    alive_nodes = []
    sem_scan = asyncio.Semaphore(SCAN_CONCURRENCY)
    async def scan_task(ip, port):
        async with sem_scan:
            res = await port_scanner(ip, port)
            if res:
                alive_nodes.append(res)
    await asyncio.gather(*(scan_task(ip, port) for ip, port in all_tasks))
    print(f"[*] 探测结束，开放端口的 IP 数量: {len(alive_nodes)}")
    if not alive_nodes:
        open(OUTPUT, 'w').close()
        print("[!] 未发现存活端口。")
        return

    print(f"[*] 第二阶段：正在通过接口验证可用性...")
    sem_check = asyncio.Semaphore(CHECK_CONCURRENCY)
    async with aiohttp.ClientSession() as session:
        check_tasks = [check_via_interface(session, node, sem_check) for node in alive_nodes]
        final_results = await asyncio.gather(*check_tasks)
    valid_list = [r for r in final_results if r]
    print(f"[*] 接口验证通过数量: {len(valid_list)}")
    if not valid_list:
        open(OUTPUT, 'w').close()
        print("[!] 没有通过接口验证的代理。")
        return

    unique_ips = set(addr.split(':')[0] for addr in valid_list)
    print(f"[*] 第三阶段：查询 {len(unique_ips)} 个唯一 IP 的地理位置信息...")
    geo_sem = asyncio.Semaphore(GEO_CONCURRENCY)
    async with aiohttp.ClientSession() as session:
        geo_tasks = [fetch_geo_info(session, ip, geo_sem) for ip in unique_ips]
        geo_results = await asyncio.gather(*geo_tasks)
    ip_geo_map = {ip: (geo if geo else {'country': '未知', 'region': '未知', 'org_type': '未知', 'isp': '', 'as': ''})
                  for ip, geo in zip(unique_ips, geo_results)}

    output_lines = format_proxy_output(valid_list, ip_geo_map)
    os.makedirs(os.path.dirname(OUTPUT), exist_ok=True)
    with open(OUTPUT, 'w', encoding='utf-8') as f:
        f.write('\n'.join(output_lines))

    print("\n📌 生成结果示例：")
    for line in output_lines[:10]:
        print(line)
    if len(output_lines) > 10:
        print("...")
    print(f"\n[DONE] 最终筛选出 {len(valid_list)} 个可用代理，已保存至 {OUTPUT}")

if __name__ == "__main__":
    asyncio.run(main())
