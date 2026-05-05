#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IPTV 源自动更新 - HTTP 探测版 (配置驱动, 支持分组叠加修改)
使用 fofa.icu API 搜索候选 host，仅探测一个测试 UDP 流。
找到可用 host 后，统一替换对应分组内所有频道的 IP。
同一输出文件可被多个分组顺序修改，不覆盖其他分组的频道。
全局 host 去重，避免分组间重复使用同一 IP。
输出文件列表写入 output_files.txt，供 CI 动态 git add。

环境变量: FOFA_KEY (fofa.icu 的 API Key)
"""

import os, re, json, base64, requests
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

CONFIG_PATH  = os.path.join(os.path.dirname(__file__), "..", "config.json")
THREADS      = 50
HTTP_TIMEOUT = 3

USED_HOSTS  = set()
RAW_CACHE   = {}        # 原始下载文件  {文件名: 内容}
FILE_CACHE  = {}        # 输出文件累积内容 {输出路径: 内容}


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


def search_fofa(key, query):
    q_b64 = base64.b64encode(query.encode()).decode()
    resp = requests.get(
        "https://fofa.icu/api/v1/search/all",
        params={
            "key": key, "qbase64": q_b64,
            "fields": "host,ip,port",
            "page": 1, "size": 10000, "full": "false"
        },
        timeout=30
    )
    resp.raise_for_status()
    data = resp.json()
    if data.get("error"):
        raise RuntimeError(data.get("errmsg", "FOFA API 错误"))

    hosts = []
    for r in data.get("results", []):
        if not isinstance(r, list):
            continue
        h  = (r[0] or "").strip()
        ip = (r[1] or "").strip()
        p  = str(r[2]).strip() if len(r) > 2 and r[2] else ""
        base = h if h else ip
        if not base:
            continue
        # 避免重复端口
        if p and ":" not in base:
            hosts.append(f"{base}:{p}")
        else:
            hosts.append(base)

    seen = set()
    uniq = []
    for x in hosts:
        if x not in seen:
            seen.add(x)
            uniq.append(x)
    return uniq


def download_raw(repo, filename):
    url = f"https://raw.githubusercontent.com/{repo}/main/{filename}"
    try:
        r = requests.get(url, timeout=15)
        return r.text if r.status_code == 200 else None
    except Exception:
        return None


def extract_test_stream(text):
    for line in text.splitlines():
        if line.startswith("http") and "/udp/" in line:
            s = line.split("/udp/")[-1].strip()
            if s and not s.startswith("#"):
                return s
    return None


def test_host_http(host, udp_stream):
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

def find_best_host(candidates, test_udp, require_domain, group_name):
    fresh = [h for h in candidates if h not in USED_HOSTS]
    if not fresh:
        print(f"[{group_name}] 所有候选 host 已被占用")
        return None

    def _test_batch(hlist, label):
        if not hlist:
            return None
        print(f"[{group_name}] {label}，共 {len(hlist)} 个")
        cnt = 0
        with ThreadPoolExecutor(max_workers=THREADS) as ex:
            fut = {ex.submit(test_host_http, h, test_udp): h for h in hlist}
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

    if require_domain:
        domains = [h for h in fresh if not re.match(r"\d+\.\d+\.\d+\.\d+", h.split(":")[0])]
        ips     = [h for h in fresh if re.match(r"\d+\.\d+\.\d+\.\d+", h.split(":")[0])]
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
    repo           = cfg.get("target_repo")
    m3u_file       = cfg.get("target_m3u")
    txt_file       = cfg.get("target_txt")
    out_m3u        = cfg["output_m3u"]
    out_txt        = cfg.get("output_txt")

    print(f"\n{'='*60}\n处理分组: {name}\n{'='*60}")

    # 1. 搜索候选
    try:
        candidates = search_fofa(fofa_key, cfg["fofa_query"])
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

    # 4. 寻找可用 host
    best = find_best_host(candidates, test_udp, require_domain, name)
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

    for g in groups:
        try:
            process_group(g, fofa_key)
        except Exception as e:
            print(f"分组 {g.get('name', '?')} 异常: {e}")

    print("\n写入所有输出文件...")
    write_output()

    # ★ 关键：将输出文件列表写入 output_files.txt，供 CI 动态 git add
    with open("output_files.txt", "w", encoding="utf-8") as f:
        for path in FILE_CACHE.keys():
            f.write(path + "\n")
    print("输出文件列表已写入 output_files.txt")

    print(f"=== 任务结束 {datetime.now():%Y-%m-%d %H:%M:%S} ===")


if __name__ == "__main__":
    main()
