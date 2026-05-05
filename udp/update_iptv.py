#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
config.json 驱动的 IPTV 源更新脚本（HTTP 探测版，彻底解决卡死）
环境变量: FOFA_KEY
"""

import os, re, json, base64, requests
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

CONFIG_PATH   = os.path.join(os.path.dirname(__file__), "..", "config.json")
THREADS       = 50                # 并发数
HTTP_TIMEOUT  = 2                 # HTTP 请求超时(秒)
USED_HOSTS    = set()
FILE_CACHE    = {}                # {输出路径: 内容}


# ─── 基础工具 ────────────────────────────────────────

def load_config():
    if not os.path.exists(CONFIG_PATH):
        raise FileNotFoundError(f"配置文件不存在: {CONFIG_PATH}")
    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        raw = f.read().strip()
        if not raw: raise ValueError("config.json 为空")
        config = json.loads(raw)
    for i, g in enumerate(config):
        for field in ["name", "fofa_query", "output_m3u"]:
            if field not in g:
                raise ValueError(f"分组 {i} 缺少必填字段: {field}")
    return config

def load_fofa_key():
    key = os.getenv("FOFA_KEY")
    if not key: raise EnvironmentError("FOFA_KEY 环境变量未设置")
    return key

def search_fofa_icu(key, query):
    q_b64 = base64.b64encode(query.encode()).decode()
    resp = requests.get("https://fofa.icu/api/v1/search/all", params={
        "key": key, "qbase64": q_b64,
        "fields": "host,ip,port", "page": 1, "size": 10000, "full": "false"
    }, timeout=30)
    resp.raise_for_status()
    data = resp.json()
    if data.get("error"): raise RuntimeError(data.get("errmsg", "FOFA API 错误"))
    hosts = []
    for r in data.get("results", []):
        if isinstance(r, list):
            h = r[0] if r[0] else r[1]
            p = r[2] if len(r) > 2 and r[2] else ""
            if h: hosts.append(f"{h}:{p}" if p else h)
    # 去重
    seen = set()
    uniq = []
    for h in hosts:
        if h not in seen:
            seen.add(h); uniq.append(h)
    return uniq

def download_file(repo, filename):
    url = f"https://raw.githubusercontent.com/{repo}/main/{filename}"
    try:
        r = requests.get(url, timeout=15)
        if r.status_code == 200: return r.text
    except: pass
    return None

def extract_one_udp(text):
    for line in text.splitlines():
        if line.startswith("http") and "/udp/" in line:
            s = line.split("/udp/")[-1].strip()
            if s and not s.startswith("#"): return s
    return None

def test_stream_http(host, stream):
    """HTTP 快速探测，超时短，不卡死"""
    url = f"http://{host}/udp/{stream}"
    try:
        r = requests.get(url, stream=True, timeout=HTTP_TIMEOUT)
        if r.status_code == 200:
            chunk = r.raw.read(4096)
            if chunk and b'<html' not in chunk[:500].lower():
                return host
    except: pass
    return None

def find_best_host(candidates, test_udp, require_domain, group_name):
    global USED_HOSTS
    fresh = [h for h in candidates if h not in USED_HOSTS]
    if not fresh:
        print(f"[{group_name}] 无未使用的候选 host")
        return None
    print(f"[{group_name}] 测试 {len(fresh)} 个 host (流: {test_udp})...")
    with ThreadPoolExecutor(max_workers=THREADS) as ex:
        futures = {ex.submit(test_stream_http, h, test_udp): h for h in fresh}
        for f in as_completed(futures):
            host = f.result()
            if host:
                if require_domain and re.match(r'\d+\.\d+\.\d+\.\d+', host.split(":")[0]):
                    continue
                USED_HOSTS.add(host)
                print(f"[{group_name}] ✅ 选定 host: {host}")
                ex.shutdown(wait=False)
                return host
    print(f"[{group_name}] 未找到可用 host")
    return None

def replace_in_m3u_group(text, group_name, new_host):
    lines = text.splitlines()
    out = []
    i = 0
    while i < len(lines):
        line = lines[i]
        if line.startswith("#EXTINF") and f'group-title="{group_name}"' in line:
            out.append(line)
            if i+1 < len(lines) and lines[i+1].startswith("http") and "/udp/" in lines[i+1]:
                stream = lines[i+1].split("/udp/")[-1].strip()
                out.append(f"http://{new_host}/udp/{stream}")
                i += 2
            else:
                out.append(lines[i+1] if i+1 < len(lines) else "")
                i += 2
        else:
            out.append(line)
            i += 1
    return "\n".join(out)

def replace_in_txt_genre(text, group_name, new_host):
    lines = text.splitlines()
    out = []
    in_grp = False
    for line in lines:
        if group_name in line and "#genre#" in line:
            in_grp = True; out.append(line); continue
        if in_grp and "#genre#" in line:
            in_grp = False; out.append(line); continue
        if in_grp and "," in line:
            name, url = line.split(",", 1)
            if "/udp/" in url:
                stream = url.split("/udp/")[-1].strip()
                out.append(f"{name},http://{new_host}/udp/{stream}")
            else: out.append(line)
        else:
            out.append(line)
    return "\n".join(out)

def update_global_file(path, content):
    FILE_CACHE[path] = content

def write_all_output():
    for path, content in FILE_CACHE.items():
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        print(f"  已写入: {path}")

# ─── 处理分组 ────────────────────────────────────────

def process_group(g, fofa_key):
    name = g["name"]
    test_udp = g.get("test_udp")
    require_domain = g.get("require_domain", False)
    repo = g.get("target_repo")
    m3u_file = g.get("target_m3u")
    txt_file = g.get("target_txt")
    out_m3u = g["output_m3u"]
    out_txt = g.get("output_txt")

    print(f"\n{'='*60}\n处理分组: {name}\n{'='*60}")

    # 1. 搜索
    try:
        candidates = search_fofa_icu(fofa_key, g["fofa_query"])
        if not candidates:
            print("未搜到 host"); return
        print(f"候选 host: {len(candidates)} 个")
    except Exception as e:
        print(f"FOFA 搜索失败: {e}"); return

    # 2. 下载原始文件
    dl = []
    if repo and m3u_file: dl.append((repo, m3u_file))
    if repo and txt_file: dl.append((repo, txt_file))
    for r, f in dl:
        if f not in FILE_CACHE:
            print(f"  下载 {r}/{f} ...")
            content = download_file(r, f)
            FILE_CACHE[f] = content if content is not None else ""

    m3u_raw = FILE_CACHE.get(m3u_file, "") if m3u_file else ""
    txt_raw = FILE_CACHE.get(txt_file, "") if txt_file else ""

    # 3. 测试流
    if not test_udp:
        test_udp = extract_one_udp(m3u_raw)
        if not test_udp:
            print("无法获取测试流，跳过"); return
    print(f"测试流: {test_udp}")

    # 4. 找 host
    best = find_best_host(candidates, test_udp, require_domain, name)
    if not best: return

    # 5. 替换并更新缓存
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    if m3u_raw:
        new_m3u = replace_in_m3u_group(m3u_raw, name, best)
        new_m3u = re.sub(r"# 更新时间:.*", f"# 更新时间: {ts}", new_m3u)
        update_global_file(out_m3u, new_m3u)
        print(f"M3U 已更新 -> {out_m3u}")
    if txt_raw and out_txt:
        new_txt = replace_in_txt_genre(txt_raw, name, best)
        new_txt = re.sub(r"# 更新时间:.*", f"# 更新时间: {ts}", new_txt)
        update_global_file(out_txt, new_txt)
        print(f"TXT 已更新 -> {out_txt}")

def main():
    print(f"=== IPTV 更新开始 {datetime.now():%Y-%m-%d %H:%M:%S} ===")
    try:
        groups = load_config()
        fofa_key = load_fofa_key()
    except Exception as e:
        print(f"初始化失败: {e}"); return

    for g in groups:
        try:
            process_group(g, fofa_key)
        except Exception as e:
            print(f"分组 {g.get('name','?')} 异常: {e}")

    print("\n写入所有输出文件...")
    write_all_output()
    print(f"=== 任务结束 {datetime.now():%Y-%m-%d %H:%M:%S} ===")

if __name__ == "__main__":
    main()
