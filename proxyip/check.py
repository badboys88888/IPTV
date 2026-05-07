#!/usr/bin/env python3
import asyncio
import aiohttp
import csv
import json
import random
import sys
import geoip2.database
from datetime import datetime

INPUT = 'proxyip/ip.txt'
OUTPUT = 'proxyip/results.csv'
CONCURRENCY = 20
TIMEOUT = 15
RETRY = 2
URL = 'https://dawn-lab-5568.177866120.workers.dev/check?proxyip={}'
GEO_DB_PATH = 'proxyip/Country.mmdb'

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
]

_geo_reader = None

def get_geo_reader():
    global _geo_reader
    if _geo_reader is None:
        _geo_reader = geoip2.database.Reader(GEO_DB_PATH)
    return _geo_reader

def geo_lookup(ip):
    try:
        ip_only = ip.split(':')[0]
        reader = get_geo_reader()
        response = reader.country(ip_only)
        country = response.country.name or ''
        iso_code = response.country.iso_code or ''
        return f"{country} ({iso_code})"
    except Exception:
        return 'N/A'

def parse_ips(filepath):
    ips = []
    with open(filepath, encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            first = line.split('\t')[0].split(',')[0].strip()
            if not first:
                continue
            if first.lower() in ('input', 'proxyip', 'ip'):
                continue
            ips.append(first)
    return ips

def log(msg):
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"[{ts}] {msg}", flush=True)

def print_progress(progress):
    done = progress['done']
    total = progress['total']
    success = progress['success']
    blocked = progress['blocked']
    error = progress['error']
    pct = done / total * 100 if total else 0
    bar_len = 30
    filled = int(bar_len * done / total) if total else 0
    bar = '█' * filled + '░' * (bar_len - filled)
    print(
        f"\r[{bar}] {pct:5.1f}% | {done}/{total} | "
        f"✅ 成功:{success}  🚫 拦截:{blocked}  ❌ 报错:{error}",
        end='', flush=True
    )

async def fetch(session, ipraw, sem, progress):
    if ':' not in ipraw:
        ipraw = ipraw + ':443'

    last_error = ''
    async with sem:
        await asyncio.sleep(random.uniform(0.5, 2.0))

        for attempt in range(1, RETRY + 2):
            try:
                headers = {
                    "User-Agent": random.choice(USER_AGENTS),
                    "Accept": "application/json, text/plain, */*",
                    "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
                    "Referer": "https://check.proxyip.cmliussss.net/",
                    "Origin": "https://check.proxyip.cmliussss.net",
                }
                async with session.get(URL.format(ipraw), headers=headers) as r:
                    text = await r.text()

                    if text.strip().startswith('<'):
                        progress['blocked'] += 1
                        progress['done'] += 1
                        print_progress(progress)
                        return ipraw, {"error": "blocked (returned HTML)", "success": False}

                    try:
                        data = json.loads(text)
                    except Exception:
                        data = {"raw": text, "error": "invalid JSON"}

                    success_val = data.get('success', '')
                    if success_val is True or str(success_val).upper() == 'TRUE':
                        progress['success'] += 1
                        # 成功的单独打印一行
                        print('', flush=True)  # 换行
                        colo = data.get('colo', '?')
                        rt = data.get('responseTime', '?')
                        log(f"✅ {ipraw}  colo={colo}  响应={rt}ms")
                    elif data.get('error'):
                        progress['error'] += 1

                    progress['done'] += 1
                    print_progress(progress)
                    return ipraw, data

            except asyncio.TimeoutError:
                last_error = f"timeout (attempt {attempt})"
            except aiohttp.ClientError as e:
                last_error = f"client error: {e} (attempt {attempt})"
            except Exception as e:
                last_error = f"unexpected: {e} (attempt {attempt})"

            if attempt <= RETRY:
                await asyncio.sleep(random.uniform(1, 3))

    progress['error'] += 1
    progress['done'] += 1
    print_progress(progress)
    return ipraw, {"error": last_error}

async def main():
    ips = parse_ips(INPUT)
    total = len(ips)

    log(f"开始检测，共 {total} 个 IP")
    log(f"并发={CONCURRENCY}  超时={TIMEOUT}s  重试={RETRY}次")
    log(f"检测接口: {URL.split('?')[0]}")
    print('-' * 60, flush=True)

    sem = asyncio.Semaphore(CONCURRENCY)
    timeout = aiohttp.ClientTimeout(total=TIMEOUT, connect=5, sock_read=TIMEOUT)
    connector = aiohttp.TCPConnector(limit=CONCURRENCY, ttl_dns_cache=300)
    progress = {'done': 0, 'total': total, 'success': 0, 'blocked': 0, 'error': 0}

    start = asyncio.get_event_loop().time()

    async with aiohttp.ClientSession(timeout=timeout, connector=connector) as sess:
        tasks = [fetch(sess, ip, sem, progress) for ip in ips]
        results = await asyncio.gather(*tasks, return_exceptions=False)

    elapsed = asyncio.get_event_loop().time() - start
    print('\n' + '-' * 60, flush=True)
    log(f"完成！耗时 {elapsed:.0f}s")
    log(f"总计={total}  ✅ 成功={progress['success']}  🚫 拦截={progress['blocked']}  ❌ 报错={progress['error']}")

    with open(OUTPUT, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow([
            'input', 'proxyIP', 'portRemote', 'success', 'colo',
            'responseTime', 'message', 'timestamp', 'error',
            'raw', 'colo_value', 'location'
        ])
        for ipraw, data in results:
            if isinstance(data, dict):
                err_msg = data.get('error', '')
                colo_val = data.get('colo', '')
                ip_for_geo = data.get('proxyIP', ipraw)
                location = geo_lookup(ip_for_geo)
                success_val = data.get('success', '')
                writer.writerow([
                    ipraw,
                    data.get('proxyIP', ''),
                    data.get('portRemote', ''),
                    success_val,
                    data.get('colo', ''),
                    data.get('responseTime', ''),
                    data.get('message', ''),
                    data.get('timestamp', ''),
                    err_msg,
                    str(data.get('raw', '')),
                    colo_val,
                    location
                ])
            else:
                location = geo_lookup(ipraw)
                writer.writerow([
                    ipraw, '', '', '', '', '', '', '',
                    'unexpected response', '', '', location
                ])

    if _geo_reader is not None:
        _geo_reader.close()

    log(f"结果已保存到 {OUTPUT}")

if __name__ == "__main__":
    asyncio.run(main())
