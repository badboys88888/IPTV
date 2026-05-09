import asyncio
import aiohttp
import ipaddress
import random
import os
from collections import defaultdict

# === 配置区 ===
INPUT = 'scan/ip.txt'
OUTPUT = 'scan/useful_proxies.txt'

SCAN_CONCURRENCY = 5000   # 端口探测并发
CHECK_CONCURRENCY = 50    # 接口精测并发
GEO_CONCURRENCY = 20      # 地理位置查询并发
# 常见的 Cloudflare 备用 HTTPS 端口
TARGET_PORTS = [443, 8443, 2053, 2083, 2087, 2093, 2096, 8080, 30001, 30006, 10443, 50001, 20002, 12345, 8081]
MAX_IPS_PER_NET = 999999    # 每个大网段随机抽取的样本数
CHECK_URL = 'https://dawn-lab-5568.177866120.workers.dev/check?proxyip={}'

# 地理位置查询 API
GEO_API_URL = 'http://ip-api.com/json/{}?fields=status,country,countryCode,regionName,isp,as,query'

# 国家代码 -> 中文名称映射
COUNTRY_MAP = {
    "TW": "台湾", "HK": "香港", "JP": "日本", "SG": "新加坡", "US": "美国",
    "KR": "韩国", "DE": "德国", "GB": "英国", "FR": "法国", "CA": "加拿大",
    "AU": "澳大利亚", "NL": "荷兰", "BR": "巴西", "IN": "印度", "RU": "俄罗斯",
    "IT": "意大利", "ES": "西班牙", "SE": "瑞典", "CH": "瑞士", "PL": "波兰",
    "TR": "土耳其", "AR": "阿根廷", "MX": "墨西哥", "ID": "印度尼西亚",
    "TH": "泰国", "VN": "越南", "PH": "菲律宾", "MY": "马来西亚",
    "UA": "乌克兰", "CZ": "捷克", "RO": "罗马尼亚", "HU": "匈牙利",
    "FI": "芬兰", "NO": "挪威", "DK": "丹麦", "PT": "葡萄牙",
    "BE": "比利时", "AT": "奥地利", "GR": "希腊", "NZ": "新西兰",
    "ZA": "南非", "EG": "埃及", "IL": "以色列", "SA": "沙特阿拉伯",
    "AE": "阿联酋", "PK": "巴基斯坦", "CN": "中国", "MO": "澳门",
    "AF": "阿富汗", "AL": "阿尔巴尼亚", "DZ": "阿尔及利亚", "AD": "安道尔",
    "AO": "安哥拉", "AG": "安提瓜和巴布达", "AM": "亚美尼亚", "AZ": "阿塞拜疆",
    "BS": "巴哈马", "BH": "巴林", "BD": "孟加拉国", "BB": "巴巴多斯",
    "BY": "白俄罗斯", "BZ": "伯利兹", "BJ": "贝宁", "BT": "不丹",
    "BO": "玻利维亚", "BA": "波黑", "BW": "博茨瓦纳", "BN": "文莱",
    "BG": "保加利亚", "BF": "布基纳法索", "BI": "布隆迪", "KH": "柬埔寨",
    "CM": "喀麦隆", "CV": "佛得角", "CF": "中非", "TD": "乍得",
    "CL": "智利", "CO": "哥伦比亚", "KM": "科摩罗", "CG": "刚果（布）",
    "CD": "刚果（金）", "CR": "哥斯达黎加", "CI": "科特迪瓦", "HR": "克罗地亚",
    "CU": "古巴", "CY": "塞浦路斯", "DJ": "吉布提", "DM": "多米尼克",
    "DO": "多米尼加", "EC": "厄瓜多尔", "SV": "萨尔瓦多", "GQ": "赤道几内亚",
    "ER": "厄立特里亚", "EE": "爱沙尼亚", "SZ": "斯威士兰", "ET": "埃塞俄比亚",
    "FJ": "斐济", "GA": "加蓬", "GM": "冈比亚", "GE": "格鲁吉亚",
    "GH": "加纳", "GD": "格林纳达", "GT": "危地马拉", "GN": "几内亚",
    "GW": "几内亚比绍", "GY": "圭亚那", "HT": "海地", "HN": "洪都拉斯",
    "IS": "冰岛", "IR": "伊朗", "IQ": "伊拉克", "IE": "爱尔兰",
    "JM": "牙买加", "JO": "约旦", "KZ": "哈萨克斯坦", "KE": "肯尼亚",
    "KI": "基里巴斯", "KP": "朝鲜", "KW": "科威特", "KG": "吉尔吉斯斯坦",
    "LA": "老挝", "LV": "拉脱维亚", "LB": "黎巴嫩", "LS": "莱索托",
    "LR": "利比里亚", "LY": "利比亚", "LI": "列支敦士登", "LT": "立陶宛",
    "LU": "卢森堡", "MG": "马达加斯加", "MW": "马拉维", "MV": "马尔代夫",
    "ML": "马里", "MT": "马耳他", "MH": "马绍尔群岛", "MR": "毛里塔尼亚",
    "MU": "毛里求斯", "FM": "密克罗尼西亚", "MD": "摩尔多瓦", "MC": "摩纳哥",
    "MN": "蒙古", "ME": "黑山", "MA": "摩洛哥", "MZ": "莫桑比克",
    "MM": "缅甸", "NA": "纳米比亚", "NR": "瑙鲁", "NP": "尼泊尔",
    "NI": "尼加拉瓜", "NE": "尼日尔", "NG": "尼日利亚", "MK": "北马其顿",
    "OM": "阿曼", "PW": "帕劳", "PS": "巴勒斯坦", "PA": "巴拿马",
    "PG": "巴布亚新几内亚", "PY": "巴拉圭", "PE": "秘鲁", "QA": "卡塔尔",
    "RW": "卢旺达", "KN": "圣基茨和尼维斯", "LC": "圣卢西亚", "VC": "圣文森特和格林纳丁斯",
    "WS": "萨摩亚", "SM": "圣马力诺", "ST": "圣多美和普林西比", "SN": "塞内加尔",
    "RS": "塞尔维亚", "SC": "塞舌尔", "SL": "塞拉利昂", "SK": "斯洛伐克",
    "SI": "斯洛文尼亚", "SB": "所罗门群岛", "SO": "索马里", "SS": "南苏丹",
    "LK": "斯里兰卡", "SD": "苏丹", "SR": "苏里南", "SY": "叙利亚",
    "TJ": "塔吉克斯坦", "TZ": "坦桑尼亚", "TL": "东帝汶", "TG": "多哥",
    "TO": "汤加", "TT": "特立尼达和多巴哥", "TN": "突尼斯", "TM": "土库曼斯坦",
    "TV": "图瓦卢", "UG": "乌干达", "UY": "乌拉圭", "UZ": "乌兹别克斯坦",
    "VU": "瓦努阿图", "VA": "梵蒂冈", "VE": "委内瑞拉", "YE": "也门",
    "ZM": "赞比亚", "ZW": "津巴布韦",
}

# ISP/AS 关键词 -> 运营商类型/中文名称映射
ORG_MAP = {
    "oracle": "甲骨文云", "oracle corporation": "甲骨文云",
    "amazon": "亚马逊云", "amazon.com": "亚马逊云", "aws": "亚马逊云",
    "google": "谷歌云", "microsoft": "Azure", "azure": "Azure",
    "cloudflare": "Cloudflare", "alibaba": "阿里云", "tencent": "腾讯云",
    "huawei": "华为云", "ibm": "IBM云",
    "comcast": "康卡斯特", "verizon": "威瑞森电信", "at&t": "AT&T", "spectrum": "特许通讯",
    "vodafone": "沃达丰",
    "hinet": "中华电信", "chunghwa": "中华电信", "twm": "台湾大哥大", "fareastone": "远传电信",
    "sk telecom": "SK电信", "kt corp": "韩国电信", "lg uplus": "LG U+",
    "hkbn": "香港宽频", "hkt": "香港电讯", "pccw": "香港电讯",
    "digitalocean": "机房", "linode": "机房", "vultr": "机房", "ovh": "机房", "hetzner": "机房",
    "serverius": "机房", "m247": "机房", "cogent": "机房", "zenlayer": "机房", "choopa": "机房",
    "leaseweb": "机房", "fdcservers": "FDC机房", "ctgserver": "CTG机房",
    "private customer": "家宽", "private": "家宽", "customer": "家宽",
    "charter": "Spectrum", "frontier": "Frontier", "sky digital": "Sky",
    "sk broadband": "SK宽带", "korea telecom": "韩国电信", "sony network": "So-net",
    "oneprovider": "机房", "oneasiahost": "机房", "nexeon": "机房",
    "lamhosting": "机房", "ipxo": "机房", "hostkey": "机房",
    "cgi global": "机房", "bytevirt": "机房", "austole": "机房",
    "veesp": "机房", "sakura": "机房", "pittqiao": "机房",
    "fomo crew": "机房", "emagine": "机房", "dromatics": "机房",
    "digital united": "机房", "akile": "机房", "akari": "机房",
    "a.i.p. italia": "机房", "enterprise": "企宽", "cake home": "家宽"
}


async def port_scanner(ip, port):
    """第一阶段：快速探测 TCP 端口存活"""
    try:
        conn = asyncio.open_connection(str(ip), port)
        _, writer = await asyncio.wait_for(conn, timeout=1.5)
        writer.close()
        await writer.wait_closed()
        return f"{ip}:{port}"
    except:
        return None


async def check_via_interface(session, proxy_addr, sem):
    """第二阶段：将存活 IP 喂给接口精测"""
    async with sem:
        full_url = CHECK_URL.format(proxy_addr)
        try:
            async with session.get(full_url, timeout=15) as r:
                if r.status == 200:
                    data = await r.json()
                    if data.get('success') is True:
                        colo = data.get('colo', '')
                        response_time = data.get('responseTime', '')
                        print(f"🔥 [成功] {proxy_addr} | colo: {colo} | 响应: {response_time}ms")
                        return proxy_addr
        except:
            pass
    return None


async def fetch_geo_info(session, ip, sem):
    """查询 IP 的地理位置和运营商信息，返回包含国家、地区、运营商类型等信息的字典"""
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
                        
                        # 匹配运营商类型
                        org_type = match_org(isp, as_info)
                        return {
                            'country': country_name,
                            'region': region,
                            'org_type': org_type,
                            'isp': isp,
                            'as': as_info
                        }
        except Exception as e:
            print(f"⚠️ 地理位置查询失败 {ip}: {e}")
    return None


def match_org(isp, as_info):
    """根据 ISP 和 AS 信息匹配预设的运营商分类"""
    text = (isp + " " + as_info).lower()
    for key, val in ORG_MAP.items():
        if key in text:
            return val
    if isp:
        return isp[:20]
    return "未知"


def format_proxy_output(valid_list, ip_geo_map):
    """
    按国家分组，生成目标格式：
    #国家名
    IP:PORT#地区-编号-运营商
    """
    # 按国家分组
    groups = defaultdict(list)
    for proxy in valid_list:
        ip = proxy.split(':')[0]
        geo = ip_geo_map.get(ip, {})
        country = geo.get('country', '未知')
        region = geo.get('region', '未知')
        org_type = geo.get('org_type', '未知')
        # 如果地区为空或未知，则用国家名代替
        if not region or region == '未知':
            region = country
        groups[country].append((proxy, region, org_type))
    
    output_lines = []
    # 对每个国家内的代理排序（按 IP 排序保证编号稳定）
    for country in sorted(groups.keys()):
        output_lines.append(f"#{country}")
        proxies = groups[country]
        # 排序：可以按 IP 排序，也可以保留原顺序
        proxies.sort(key=lambda x: x[0])  # 按 IP:PORT 排序
        for idx, (proxy, region, org) in enumerate(proxies, start=1):
            # 编号格式三位数字
            number = f"{idx:03d}"
            comment = f"{region}-{number}-{org}"
            output_lines.append(f"{proxy}#{comment}")
    return output_lines


async def main():
    if not os.path.exists(INPUT):
        print(f"[!] 找不到输入文件: {INPUT}")
        return

    # 1. 解析 ip.txt
    all_tasks = []
    with open(INPUT, 'r') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
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

    # 2. 端口快扫
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

    # 3. 接口精测
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

    # 4. 地理位置查询（对唯一 IP 进行缓存）
    unique_ips = set(addr.split(':')[0] for addr in valid_list)
    print(f"[*] 第三阶段：查询 {len(unique_ips)} 个唯一 IP 的地理位置信息...")
    geo_sem = asyncio.Semaphore(GEO_CONCURRENCY)
    async with aiohttp.ClientSession() as session:
        geo_tasks = [fetch_geo_info(session, ip, geo_sem) for ip in unique_ips]
        geo_results = await asyncio.gather(*geo_tasks)

    # 构建 IP -> 地理信息 的映射
    ip_geo_map = {}
    for ip, geo in zip(unique_ips, geo_results):
        if geo is not None:
            ip_geo_map[ip] = geo
        else:
            ip_geo_map[ip] = {'country': '未知', 'region': '未知', 'org_type': '未知', 'isp': '', 'as': ''}

    # 5. 生成新格式的输出
    output_lines = format_proxy_output(valid_list, ip_geo_map)

    # 写入文件
    os.makedirs(os.path.dirname(OUTPUT), exist_ok=True)
    with open(OUTPUT, 'w', encoding='utf-8') as f:
        f.write('\n'.join(output_lines))

    # 控制台打印前几条示例
    print("\n📌 生成结果示例（前10行）：")
    for line in output_lines[:10]:
        print(line)
    if len(output_lines) > 10:
        print("...")
    print(f"\n[DONE] 最终筛选出 {len(valid_list)} 个可用代理，已保存至 {OUTPUT}")


if __name__ == "__main__":
    asyncio.run(main())
