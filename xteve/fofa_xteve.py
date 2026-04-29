"""
FOFA xteve 搜索 + M3U 链接验证 + 展开详细频道
使用 fofa.icu 第三方 API + CSV 缓存
本地运行需要: fofa_api.txt（内容: key=your_api_key）
GitHub Actions: 从环境变量 FOFA_KEY 读取
"""

import os
import re
import csv
import requests
import base64
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict

# ── 配置 ──────────────────────────────────────────────
API_FILE     = "fofa_api.txt"
CACHE_FILE   = "xteve/fofa_hosts.csv"
OUTPUT_M3U   = "xteve/xteve.m3u"
EXPANDED_M3U = "xteve/xteve_expanded.m3u"
QUERY        = 'header="Content-Type: application/xml" && body="xteve"'
PAGE_SIZE    = 10000
TIMEOUT      = 10
MAX_WORKERS  = 30
MIN_CHANNELS = 5
CACHE_HOURS  = 48
# ──────────────────────────────────────────────────────


def load_key():
    key = os.getenv("FOFA_KEY")
    if key:
        print("✔ 从环境变量读取 API Key")
        return key
    try:
        cfg = {}
        with open(API_FILE, "r", encoding="utf-8") as f:
            for line in f:
                if "=" in line:
                    k, v = line.strip().split("=", 1)
                    cfg[k.strip()] = v.strip()
        key = cfg.get("key") or cfg.get("FOFA_KEY")
        if not key:
            raise ValueError("未找到 key")
        print(f"✔ 从 {API_FILE} 读取 API Key（{key[:8]}...）")
        return key
    except FileNotFoundError:
        print(f"❌ 未设置 FOFA_KEY 环境变量，也找不到 {API_FILE}")
        exit(1)


def cache_valid():
    if not os.path.exists(CACHE_FILE):
        return False
    age = datetime.now() - datetime.fromtimestamp(os.path.getmtime(CACHE_FILE))
    if age < timedelta(hours=CACHE_HOURS):
        print(f"✔ 缓存有效（{int(age.total_seconds()/3600)} 小时前更新），跳过 FOFA 请求")
        return True
    print(f"⚠️  缓存已过期，重新获取")
    return False


def load_cache():
    items = []
    with open(CACHE_FILE, "r", encoding="utf-8", newline="") as f:
        for row in csv.DictReader(f):
            items.append((row["host"], row["country"]))
    print(f"✔ 从缓存加载 {len(items)} 条记录")
    return items


def save_cache(items):
    os.makedirs(os.path.dirname(CACHE_FILE), exist_ok=True)
    with open(CACHE_FILE, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["host", "country", "fetched_at"])
        writer.writeheader()
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        for host, country in items:
            writer.writerow({"host": host, "country": country, "fetched_at": now})
    print(f"✔ 已缓存 {len(items)} 条到 {CACHE_FILE}")


def search_fofa_icu(key):
    q_b64 = base64.b64encode(QUERY.encode()).decode()
    resp = requests.get("https://fofa.icu/api/v1/search/all", params={
        "key": key,
        "qbase64": q_b64,
        "fields": "host,country",
        "page": 1,
        "size": PAGE_SIZE,
        "full": "false",
    }, timeout=30)
    resp.raise_for_status()
    data = resp.json()
    if data.get("error"):
        raise RuntimeError(f"API 错误: {data.get('errmsg', data)}")
    items = []
    for r in data.get("results", []):
        if isinstance(r, list) and len(r) >= 2:
            items.append((r[0], r[1] or "Unknown"))
        elif isinstance(r, str):
            items.append((r, "Unknown"))
    return items, data.get("size", 0)


def build_m3u_url(host):
    h = host.replace("https://", "").replace("http://", "").rstrip("/")
    return f"http://{h}/m3u/xteve.m3u"


def count_channels(text):
    return text.count("#EXTINF")


def verify_xteve(host, country):
    url = build_m3u_url(host)
    try:
        r = requests.get(url, timeout=TIMEOUT, allow_redirects=True)
        if r.status_code == 200:
            content = r.text
            if "#EXTM3U" not in content and "#EXT" not in content:
                return host, country, url, "⚠️  非 M3U 内容", 0
            ch_count = count_channels(content)
            if ch_count == 0:
                return host, country, url, "⚠️  空 M3U（0频道）", 0
            elif ch_count < MIN_CHANNELS:
                return host, country, url, f"⚠️  频道太少({ch_count}个)", ch_count
            else:
                return host, country, url, f"✅ 有效({ch_count}频道)", ch_count
        else:
            return host, country, url, f"❌ HTTP {r.status_code}", 0
    except requests.exceptions.ConnectTimeout:
        return host, country, url, "❌ 连接超时", 0
    except requests.exceptions.ReadTimeout:
        return host, country, url, "❌ 读取超时", 0
    except requests.exceptions.ConnectionError:
        return host, country, url, "❌ 连接拒绝", 0
    except Exception as e:
        return host, country, url, f"❌ 错误: {e}", 0


def save_m3u(valid_by_country):
    os.makedirs(os.path.dirname(OUTPUT_M3U), exist_ok=True)
    with open(OUTPUT_M3U, "w", encoding="utf-8") as f:
        f.write("#EXTM3U\n")
        f.write(f"# 更新时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        for country in sorted(valid_by_country.keys()):
            entries = sorted(valid_by_country[country], key=lambda x: x[1], reverse=True)
            f.write(f"# ── {country} ──\n")
            for url, ch_count in entries:
                f.write(f"#EXTINF:-1 group-title=\"{country}\",xteve [{ch_count}频道]\n")
                f.write(f"{url}\n")
            f.write("\n")
    print(f"✔ 汇总 M3U 已保存到 {OUTPUT_M3U}")


def expand_m3u(valid_by_country):
    """展开每个 xteve 源里的实际频道，合并去重生成详细 M3U"""
    os.makedirs(os.path.dirname(EXPANDED_M3U), exist_ok=True)
    seen_source_urls = set()   # 已处理的 xteve 源，避免重复下载
    seen_ch_urls = set()       # 已写入的频道 URL，全局去重
    total_channels = 0

    with open(EXPANDED_M3U, "w", encoding="utf-8") as out:
        out.write("#EXTM3U\n")
        out.write(f"# 展开版，更新时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")

        for country in sorted(valid_by_country.keys()):
            entries = sorted(valid_by_country[country], key=lambda x: x[1], reverse=True)

            for url, ch_count in entries:
                if url in seen_source_urls:
                    print(f"  ⏭️  跳过重复源: {url}")
                    continue
                seen_source_urls.add(url)

                print(f"  📥 展开 [{country}] {url}")
                try:
                    r = requests.get(url, timeout=15, allow_redirects=True)
                    if r.status_code != 200:
                        print(f"     ❌ HTTP {r.status_code}")
                        continue

                    lines = r.text.splitlines()
                    i = 0
                    ch_added = 0
                    while i < len(lines):
                        line = lines[i].strip()
                        if line.startswith("#EXTINF") and i + 1 < len(lines):
                            ch_url = lines[i + 1].strip()
                            if ch_url and not ch_url.startswith("#"):
                                if ch_url not in seen_ch_urls:
                                    seen_ch_urls.add(ch_url)
                                    # 替换或添加 group-title
                                    if 'group-title=' in line:
                                        line = re.sub(r'group-title="[^"]*"', f'group-title="{country}"', line)
                                    else:
                                        line = line.rstrip() + f' group-title="{country}"'
                                    out.write(f"{line}\n{ch_url}\n")
                                    ch_added += 1
                                    total_channels += 1
                                i += 2
                                continue
                        i += 1

                    print(f"     ✅ 新增 {ch_added} 个频道")

                except Exception as e:
                    print(f"     ❌ 错误: {e}")

    print(f"\n✔ 展开完成，共 {total_channels} 个唯一频道，保存到 {EXPANDED_M3U}")


def main():
    key = load_key()

    # 1. 获取 host 列表
    if cache_valid():
        items = load_cache()
    else:
        print("\n🔍 正在从 FOFA 获取数据...")
        try:
            items, total = search_fofa_icu(key)
            print(f"   总结果数: {total} 条，获取 {len(items)} 条")
            save_cache(items)
        except Exception as e:
            print(f"❌ 获取失败: {e}")
            return

    if not items:
        print("⚠️  未获取到任何结果")
        return

    # 2. 去重（同一 URL 可能被 FOFA 返回多次）
    seen = set()
    deduped = []
    for host, country in items:
        url = build_m3u_url(host)
        if url not in seen:
            seen.add(url)
            deduped.append((host, country))
    print(f"\n去重后: {len(deduped)} 个唯一 host（原 {len(items)} 条）")

    # 3. 并发验证
    print(f"开始并发验证（最少 {MIN_CHANNELS} 频道才算有效）...\n")
    print("-" * 70)

    valid_by_country = defaultdict(list)
    skip_count = 0
    invalid_count = 0

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(verify_xteve, host, country): (host, country)
                   for host, country in deduped}
        for future in as_completed(futures):
            host, country, url, status, ch_count = future.result()
            print(f"{status:30s}  [{country:15s}]  {url}")
            if "✅" in status:
                valid_by_country[country].append((url, ch_count))
            elif "⚠️" in status:
                skip_count += 1
            else:
                invalid_count += 1

    total_valid = sum(len(v) for v in valid_by_country.values())
    print("\n" + "=" * 70)
    print(f"✅ 有效: {total_valid}  |  ⚠️  跳过: {skip_count}  |  ❌ 无效: {invalid_count}")

    if not valid_by_country:
        return

    print()
    for country in sorted(valid_by_country.keys()):
        entries = sorted(valid_by_country[country], key=lambda x: x[1], reverse=True)
        total_ch = sum(e[1] for e in entries)
        print(f"🌍 {country} — {len(entries)} 个链接，共 {total_ch} 个频道")
        for u, ch in entries:
            print(f"   [{ch:4d} 频道]  {u}")

    # 4. 保存汇总 M3U
    save_m3u(valid_by_country)

    # 5. 展开详细频道
    print("\n🔄 正在展开详细频道列表...")
    expand_m3u(valid_by_country)


if __name__ == "__main__":
    main()
