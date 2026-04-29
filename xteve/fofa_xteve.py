"""
FOFA xteve 搜索 + M3U 链接验证脚本
使用 fofa.icu 第三方 API + CSV 缓存
用法: python fofa_xteve.py
本地运行需要: fofa_api.txt（内容: key=your_api_key）
GitHub Actions: 从环境变量 FOFA_KEY 读取
"""

import os
import csv
import requests
import base64
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict

# ── 配置 ──────────────────────────────────────────────
API_FILE        = "fofa_api.txt"
CACHE_FILE      = "xteve/fofa_hosts.csv"       # CSV 缓存路径
OUTPUT_FILE     = "xteve/xteve.m3u"            # 输出 M3U 路径
QUERY           = 'header="Content-Type: application/xml" && body="xteve"'
PAGE_SIZE       = 10000
TIMEOUT         = 10
MAX_WORKERS     = 30
MIN_CHANNELS    = 5
CACHE_HOURS     = 24    # 缓存有效期（小时），超过则重新从 FOFA 获取
# ──────────────────────────────────────────────────────


def load_key():
    """优先读环境变量（GitHub Actions），其次读本地文件"""
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
    """检查 CSV 缓存是否存在且在有效期内"""
    if not os.path.exists(CACHE_FILE):
        return False
    mtime = datetime.fromtimestamp(os.path.getmtime(CACHE_FILE))
    age = datetime.now() - mtime
    if age < timedelta(hours=CACHE_HOURS):
        print(f"✔ 缓存有效（{int(age.total_seconds()/3600)}小时前更新），跳过 FOFA 请求")
        return True
    print(f"⚠️  缓存已过期（{int(age.total_seconds()/3600)}小时前），重新获取")
    return False


def load_cache():
    """从 CSV 读取缓存的 host 列表"""
    items = []
    with open(CACHE_FILE, "r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            items.append((row["host"], row["country"]))
    print(f"✔ 从缓存加载 {len(items)} 条记录")
    return items


def save_cache(items):
    """保存 host 列表到 CSV"""
    os.makedirs(os.path.dirname(CACHE_FILE), exist_ok=True)
    with open(CACHE_FILE, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["host", "country", "fetched_at"])
        writer.writeheader()
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        for host, country in items:
            writer.writerow({"host": host, "country": country, "fetched_at": now})
    print(f"✔ 已缓存 {len(items)} 条记录到 {CACHE_FILE}")


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

    results = data.get("results", [])
    items = []
    for r in results:
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
    """保存结果为 M3U 格式，按国家分组"""
    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write("#EXTM3U\n")
        f.write(f"# 更新时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        for country in sorted(valid_by_country.keys()):
            entries = sorted(valid_by_country[country], key=lambda x: x[1], reverse=True)
            f.write(f"# ── {country} ──\n")
            for url, ch_count in entries:
                f.write(f"#EXTINF:-1 group-title=\"{country}\",xteve [{ch_count}频道]\n")
                f.write(f"{url}\n")
            f.write("\n")
    print(f"✔ 已保存到 {OUTPUT_FILE}")


def main():
    key = load_key()

    # 1. 获取 host 列表（优先读缓存）
    if cache_valid():
        items = load_cache()
    else:
        print(f"\n🔍 正在从 FOFA 获取数据...")
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

    # 2. 并发验证
    print(f"\n共 {len(items)} 个 host，开始并发验证（最少 {MIN_CHANNELS} 频道才算有效）...\n")
    print("-" * 70)

    valid_by_country = defaultdict(list)
    skip_count = 0
    invalid_count = 0

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(verify_xteve, host, country): (host, country)
                   for host, country in items}
        for future in as_completed(futures):
            host, country, url, status, ch_count = future.result()
            print(f"{status:30s}  [{country:15s}]  {url}")
            if "✅" in status:
                valid_by_country[country].append((url, ch_count))
            elif "⚠️" in status:
                skip_count += 1
            else:
                invalid_count += 1

    # 3. 汇总输出
    total_valid = sum(len(v) for v in valid_by_country.values())
    print("\n" + "=" * 70)
    print(f"✅ 有效: {total_valid}  |  ⚠️  跳过: {skip_count}  |  ❌ 无效: {invalid_count}")

    if valid_by_country:
        print("\n📋 按国家/地区分组：\n")
        for country in sorted(valid_by_country.keys()):
            entries = sorted(valid_by_country[country], key=lambda x: x[1], reverse=True)
            total_ch = sum(e[1] for e in entries)
            print(f"🌍 {country} — {len(entries)} 个链接，共 {total_ch} 个频道")
            for u, ch in entries:
                print(f"   [{ch:4d} 频道]  {u}")
            print()

        save_m3u(valid_by_country)

        print("\n🔄 正在展开详细频道列表...")
        expand_m3u(valid_by_country)


if __name__ == "__main__":
    main()


def expand_m3u(valid_by_country):
    """把每个有效的 xteve 链接展开成里面的实际频道，生成详细 M3U"""
    expanded_file = "xteve/xteve_expanded.m3u"
    os.makedirs(os.path.dirname(expanded_file), exist_ok=True)

    seen_urls = set()   # 去重，避免同一个频道出现两次
    total_channels = 0

    with open(expanded_file, "w", encoding="utf-8") as out:
        out.write("#EXTM3U\n")
        out.write(f"# 展开版，更新时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")

        for country in sorted(valid_by_country.keys()):
            entries = sorted(valid_by_country[country], key=lambda x: x[1], reverse=True)
            # 去重同一国家下的重复 URL
            seen_in_country = set()

            for url, ch_count in entries:
                if url in seen_in_country:
                    continue
                seen_in_country.add(url)

                print(f"  📥 展开 {url} ...")
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
                        if line.startswith("#EXTINF"):
                            # 加上国家分组
                            if 'group-title=' in line:
                                # 替换原有 group-title
                                import re
                                line = re.sub(r'group-title="[^"]*"', f'group-title="{country}"', line)
                            else:
                                line = line.replace("#EXTINF:", f'#EXTINF:') 
                                line += f' group-title="{country}"'

                            # 下一行是频道 URL
                            if i + 1 < len(lines):
                                ch_url = lines[i + 1].strip()
                                if ch_url and not ch_url.startswith("#"):
                                    if ch_url not in seen_urls:
                                        seen_urls.add(ch_url)
                                        out.write(f"{line}\n{ch_url}\n")
                                        ch_added += 1
                                        total_channels += 1
                                    i += 2
                                    continue
                        i += 1

                    print(f"     ✅ 新增 {ch_added} 个频道")

                except Exception as e:
                    print(f"     ❌ 错误: {e}")

    print(f"\n✔ 展开完成，共 {total_channels} 个唯一频道，保存到 {expanded_file}")
    return expanded_file
