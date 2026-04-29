"""
FOFA xteve 搜索 + M3U 链接验证脚本（过滤空/失效版）
使用 fofa.icu 第三方 API
用法: python fofa_xteve.py
需要: fofa_api.txt 在同目录下，内容：
  key=your_api_key
"""

import requests
import base64
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict

# ── 配置 ──────────────────────────────────────────────
API_FILE        = "fofa_api.txt"
QUERY           = 'header="Content-Type: application/xml" && body="xteve"'
PAGE_SIZE       = 10000
TIMEOUT         = 10
MAX_WORKERS     = 30
MIN_CHANNELS    = 5     # 至少包含多少个频道才算有效（过滤空/极少频道的 M3U）
# ──────────────────────────────────────────────────────


def load_api(path):
    cfg = {}
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            if "=" in line:
                k, v = line.strip().split("=", 1)
                cfg[k.strip()] = v.strip()
    if "key" not in cfg:
        raise ValueError("fofa_api.txt 需包含 key=your_api_key")
    return cfg["key"]


def build_m3u_url(host):
    h = host.replace("https://", "").replace("http://", "").rstrip("/")
    return f"http://{h}/m3u/xteve.m3u"


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


def count_channels(m3u_text):
    """统计 M3U 里的频道数量（每个 #EXTINF 代表一个频道）"""
    return m3u_text.count("#EXTINF")


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


def main():
    try:
        key = load_api(API_FILE)
        print(f"✔ 已加载 API Key（{key[:8]}...）")
    except FileNotFoundError:
        print(f"❌ 找不到 {API_FILE}")
        return

    print(f"\n🔍 正在获取数据...")
    try:
        items, total = search_fofa_icu(key)
        print(f"   总结果数: {total} 条，获取 {len(items)} 条")
    except Exception as e:
        print(f"❌ 获取失败: {e}")
        return

    if not items:
        print("⚠️  未获取到任何结果")
        return

    print(f"\n共 {len(items)} 个 host，开始并发验证（最少 {MIN_CHANNELS} 个频道才算有效）...\n")
    print("-" * 70)

    valid_by_country = defaultdict(list)   # {country: [(url, ch_count), ...]}
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

    # 汇总
    total_valid = sum(len(v) for v in valid_by_country.values())
    print("\n" + "=" * 70)
    print(f"✅ 有效: {total_valid}  |  ⚠️  跳过(空/少频道): {skip_count}  |  ❌ 无效: {invalid_count}")

    if valid_by_country:
        print("\n📋 按国家/地区分组（按频道数排序）：\n")
        for country in sorted(valid_by_country.keys()):
            entries = sorted(valid_by_country[country], key=lambda x: x[1], reverse=True)
            total_ch = sum(e[1] for e in entries)
            print(f"🌍 {country} — {len(entries)} 个链接，共 {total_ch} 个频道")
            for u, ch in entries:
                print(f"   [{ch:4d} 频道]  {u}")
            print()

        # 保存
        with open("valid_xteve.txt", "w", encoding="utf-8") as f:
            for country in sorted(valid_by_country.keys()):
                entries = sorted(valid_by_country[country], key=lambda x: x[1], reverse=True)
                f.write(f"# {country}\n")
                for u, ch in entries:
                    f.write(f"{u}  # {ch} 频道\n")
                f.write("\n")
        print("已保存到 valid_xteve.txt")


if __name__ == "__main__":
    main()
