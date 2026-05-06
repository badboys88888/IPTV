#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IPTV 源自动更新 - HTTP 探测版 (配置驱动 + 地区缓存 + 省流量)
使用 fofa.icu API 搜索候选 host（每次最多 1000 条），仅探测一个测试 UDP 流。
找到可用 host 后，统一替换对应分组内所有频道的 IP。
同一输出文件可被多个分组顺序修改，不覆盖其他分组的频道。
全局 host 去重，避免分组间重复使用同一 IP。
搜索到的 host 按地区缓存，下次运行时优先使用缓存（支持同地区优先）。
输出文件列表写入 output_files.txt，供 CI 动态 git add。

环境变量: FOFA_KEY (fofa.icu 的 API Key)
"""

import os, re, json, base64, requests, time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

CONFIG_PATH   = os.path.join(os.path.dirname(__file__), "..", "config.json")
CACHE_FILE    = os.path.join(os.path.dirname(__file__), "fofa_cache.json")
CACHE_TTL     = 86400          # 缓存有效期 24 小时（可根据需要调大）
THREADS       = 50
HTTP_TIMEOUT = 3

USED_HOSTS   = set()            # 已选定使用的 host:port 字符串
RAW_CACHE    = {}               # 原始下载文件 {文件名: 内容}
FILE_CACHE   = {}               # 输出文件累积内容 {输出路径: 内容}


# ─────────────── 基础工具 ───────────────

def load_config():
    if not os.path.exists(CONFIG_PATH):
        raise FileNotFoundError(f"配置文件不存在: {CONFIG_PATH}")
    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        raw = f.read().strip()
    if not raw:
        raise ValueError("config.json 为空")
    config = json.loads(raw)
    for i, g in enumerate(config):
        for field in ("name", "fofa_query", "output_m3u"):
            if field not in g:
                raise ValueError(f"分组 {i} 缺少必填字段: {field}")
    return config


def get_fofa_key():
    key = os.getenv("FOFA_KEY")
    if not key:
        raise EnvironmentError("环境变量 FOFA_KEY 未设置")
    return key


def load_fofa_cache():
    """加载 FOFA 缓存，返回字典 {query_b64: {'ts': timestamp, 'hosts': [...]}}"""
    if os.path.exists(CACHE_FILE):
        try:
            with open(CACHE_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}


def save_fofa_cache(cache):
    with open(CACHE_FILE, "w", encoding="utf-8") as f:
        json.dump(cache, f, ensure_ascii=False, indent=2)


def search_fofa(key, query, group_name):
    """
    搜索 FOFA，返回 host 字典列表：
    [
      {
        "host": "1.2.3.4:8080",
        "country": "中国",
        "province": "北京",
        "city": "海淀"
      },
      ...
    ]
    优先使用缓存（24 小时内有效），缓存不命中才调用 API，每次最多下载 1000 条。
    """
    q_b64 = base64.b64encode(query.encode()).decode()
    cache = load_fofa_cache()
    now = time.time()

    # 检查缓存
    if q_b64 in cache:
        entry = cache[q_b64]
        if isinstance(entry, dict) and now - entry.get("ts", 0) < CACHE_TTL:
            hosts = entry.get("hosts", [])
            if hosts:
                print(f"[{group_name}] 使用 FOFA 缓存，共 {len(hosts)} 个 host")
                return hosts

    # 请求 FOFA API（最多 1000 条）
    print(f"[{group_name}] FOFA 缓存无效或不存在，开始实时搜索（最多 1000 条）...")
    resp = requests.get(
        "https://fofa.icu/api/v1/search/all",
        params={
            "key": key, "qbase64": q_b64,
            "fields": "host,ip,port,country,province,city",
            "page": 1, "size": 1000,   # 单次下载上限，足够使用
            "full": "false"
        },
        timeout=30
    )
    resp.raise_for_status()
    data = resp.json()
    if data.get("error"):
        raise RuntimeError(data.get("errmsg", "FOFA API 错误"))

    hosts = []
    for r in data.get("results", []):
        if not isinstance(r, list) or len(r) < 4:
            continue
        host    = (r[0] or "").strip()
        ip      = (r[1] or "").strip()
        port    = str(r[2]).strip() if len(r) > 2 and r[2] else ""
        country = (r[3] or "").strip() if len(r) > 3 else ""
        province= (r[4] or "").strip() if len(r) > 4 else ""
        city    = (r[5] or "").strip() if len(r) > 5 else ""

        base = host if host else ip
        if not base:
            continue
        # 组装 host:port
        if port and ":" not in base:
            addr = f"{base}:{port}"
        else:
            addr = base

        hosts.append({
            "host":     addr,
            "country":  country,
            "province": province,
            "city":     city
        })

    # 去重
    seen = set()
    uniq = []
    for h in hosts:
        if h["host"] not in seen:
            seen.add(h["host"])
            uniq.append(h)

    # 写入缓存
    cache[q_b64] = {"ts": now, "hosts": uniq}
    save_fofa_cache(cache)

    print(f"[{group_name}] 搜索完成，获得 {len(uniq)} 个 host（已缓存）")
    return uniq


def download_raw(repo, filename):
    """下载原始频道文件"""
    url = f"https://raw.githubusercontent.com/{repo}/main/{filename}"
    try:
        r = requests.get(url, timeout=15)
        return r.text if r.status_code == 200 else None
    except Exception:
        return None


def extract_test_stream(text):
    """从 m3u 中提取第一个 /udp/xxx 格式的测试流地址"""
    for line in text.splitlines():
        if line.startswith("http") and "/udp/" in line:
            s = line.split("/udp/")[-1].strip()
            if s and not s.startswith("#"):
                return s
    return None


def test_host_http(host, udp_stream):
    """测试单个 host 是否可播放指定的 udp 流"""
    url = f"http://{host}/udp/{udp_stream}"
    try:
        r = requests.get(url, stream=True, timeout=HTTP_TIMEOUT)
        if r.status_code == 200:
            chunk = r.raw.read(4096)
            if chunk and b"<html" not in chunk[:500]:
                return host
    except Exception:
        pass
    return None


# ─────────────── 探测与选择 ───────────────

def find_best_host(candidates, test_udp, require_domain, prefer_region, group_name):
    """
    candidates: [{"host":..., "country":..., "province":..., "city":...}, ...]
    优先测试 prefer_region 指定的省份（或城市），若未指定或失败则按原逻辑（域名优先 / 全部）。
    """
    fresh = [h for h in candidates if h["host"] not in USED_HOSTS]
    if not fresh:
        print(f"[{group_name}] 所有候选 host 已被占用")
        return None

    def _test_batch(hlist, label):
        if not hlist:
            return None
        print(f"[{group_name}] {label}，共 {len(hlist)} 个")
        cnt = 0
        with ThreadPoolExecutor(max_workers=THREADS) as ex:
            fut = {ex.submit(test_host_http, h["host"], test_udp): h for h in hlist}
            for f in as_completed(fut):
                cnt += 1
                if cnt % 30 == 0 or cnt == 1:
                    print(f"  进度: {cnt}/{len(hlist)}")
                host = f.result()
                if host:
                    print(f"  在第 {cnt} 次测试成功！")
                    ex.shutdown(wait=False, cancel_futures=True)
                    return host
        return None

    # 1. 如果配置了 prefer_region，优先测试该地区的候选
    if prefer_region:
        region_hosts = [h for h in fresh if prefer_region in (h.get("province", "") or h.get("city", ""))]
        if region_hosts:
            print(f"[{group_name}] 优先测试地区: {prefer_region}")
            best = _test_batch(region_hosts, "地区优先")
            if best:
                USED_HOSTS.add(best)
                print(f"[{group_name}] ✅ 选定 host: {best}")
                return best
            print(f"[{group_name}] 指定地区不可用，回落至全部候选")
        else:
            print(f"[{group_name}] 没有找到指定地区 {prefer_region} 的候选，继续常规流程")

    # 2. 域名 / IP 优先级（与原有逻辑一致）
    if require_domain:
        domains = [h for h in fresh if not re.match(r"\d+\.\d+\.\d+\.\d+", h["host"].split(":")[0])]
        ips     = [h for h in fresh if     re.match(r"\d+\.\d+\.\d+\.\d+", h["host"].split(":")[0])]
        best = _test_batch(domains, "优先测试域名")
        if best is None:
            print(f"[{group_name}] 域名均不可用，回落测试 IP")
            best = _test_batch(ips, "回落测试 IP")
    else:
        best = _test_batch(fresh, "测试全部候选")

    if best:
        USED_HOSTS.add(best)
        print(f"[{group_name}] ✅ 选定 host: {best}")
    else:
        print(f"[{group_name}] ❌ 未找到可用 host")
    return best


# ─────────────── 文本替换 ───────────────

def replace_in_m3u(text, group_name, new_host):
    lines = text.splitlines()
    out, i = [], 0
    while i < len(lines):
        line = lines[i]
        if line.startswith("#EXTINF") and f'group-title="{group_name}"' in line:
            out.append(line)
            if i + 1 < len(lines) and lines[i + 1].startswith("http") and "/udp/" in lines[i + 1]:
                stream = lines[i + 1].split("/udp/")[-1].strip()
                out.append(f"http://{new_host}/udp/{stream}")
                i += 2
                continue
        out.append(line)
        i += 1
    return "\n".join(out)


def replace_in_txt(text, group_name, new_host):
    lines = text.splitlines()
    out, in_group = [], False
    for line in lines:
        if group_name in line and "#genre#" in line:
            in_group = True
            out.append(line)
            continue
        if in_group and "#genre#" in line:
            in_group = False
            out.append(line)
            continue
        if in_group and "," in line:
            name, url = line.split(",", 1)
            if "/udp/" in url:
                stream = url.split("/udp/")[-1].strip()
                out.append(f"{name},http://{new_host}/udp/{stream}")
            else:
                out.append(line)
        else:
            out.append(line)
    return "\n".join(out)


# ─────────────── 分组处理 ───────────────

def process_group(cfg, fofa_key):
    name           = cfg["name"]
    test_udp       = cfg.get("test_udp")
    require_domain = cfg.get("require_domain", False)
    prefer_region  = cfg.get("prefer_region")              # 优先地区（省份或城市）
    repo           = cfg.get("target_repo")
    m3u_file       = cfg.get("target_m3u")
    txt_file       = cfg.get("target_txt")
    out_m3u        = cfg["output_m3u"]
    out_txt        = cfg.get("output_txt")

    print(f"\n{'='*60}\n处理分组: {name}\n{'='*60}")

    # 1. 搜索候选（带缓存，最多 1000 条）
    try:
        candidates = search_fofa(fofa_key, cfg["fofa_query"], name)
        if not candidates:
            print(f"[{name}] 未搜到 host")
            return
        print(f"[{name}] 候选 host: {len(candidates)} 个")
    except Exception as e:
        print(f"[{name}] FOFA 搜索失败: {e}")
        return

    # 2. 下载原始文件（同名文件仅下载一次）
    if m3u_file and m3u_file not in RAW_CACHE:
        print(f"[{name}] 下载 {repo}/{m3u_file}")
        RAW_CACHE[m3u_file] = download_raw(repo, m3u_file) or ""
    if txt_file and txt_file not in RAW_CACHE:
        print(f"[{name}] 下载 {repo}/{txt_file}")
        RAW_CACHE[txt_file] = download_raw(repo, txt_file) or ""

    m3u_raw = RAW_CACHE.get(m3u_file, "") if m3u_file else ""
    txt_raw = RAW_CACHE.get(txt_file, "") if txt_file else ""

    # 3. 确定测试流
    if not test_udp:
        test_udp = extract_test_stream(m3u_raw)
        if not test_udp:
            print(f"[{name}] 无法获取测试流，跳过")
            return
    print(f"[{name}] 测试流: udp/{test_udp}")

    # 4. 寻找可用 host（支持地区优先）
    best = find_best_host(candidates, test_udp, require_domain, prefer_region, name)
    if not best:
        return

    # 5. 叠加修改输出文件
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if m3u_raw:
        cur = FILE_CACHE.get(out_m3u, m3u_raw)
        updated = replace_in_m3u(cur, name, best)
        updated = re.sub(r"# 更新时间:.*", f"# 更新时间: {ts}", updated)
        FILE_CACHE[out_m3u] = updated
        print(f"[{name}] M3U 已更新 -> {out_m3u}")

    if txt_raw and out_txt:
        cur = FILE_CACHE.get(out_txt, txt_raw)
        updated = replace_in_txt(cur, name, best)
        updated = re.sub(r"# 更新时间:.*", f"# 更新时间: {ts}", updated)
        FILE_CACHE[out_txt] = updated
        print(f"[{name}] TXT 已更新 -> {out_txt}")


def write_output():
    for path, content in FILE_CACHE.items():
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        print(f"  已写入: {path}")


# ─────────────── 入口 ───────────────

def main():
    print(f"=== IPTV 更新开始 {datetime.now():%Y-%m-%d %H:%M:%S} ===")
    try:
        groups   = load_config()
        fofa_key = get_fofa_key()
    except Exception as e:
        print(f"初始化失败: {e}")
        return

    # 可选：对完全相同的 fofa_query 只搜索一次，避免重复消耗下载量
    # 这里暂时保留每个分组独立搜索，因为缓存文件已全局复用。
    for g in groups:
        try:
            process_group(g, fofa_key)
        except Exception as e:
            print(f"分组 {g.get('name', '?')} 异常: {e}")

    print("\n写入所有输出文件...")
    write_output()

    with open("output_files.txt", "w", encoding="utf-8") as f:
        for path in FILE_CACHE.keys():
            f.write(path + "\n")
    print("输出文件列表已写入 output_files.txt")

    print(f"=== 任务结束 {datetime.now():%Y-%m-%d %H:%M:%S} ===")


if __name__ == "__main__":
    main()
