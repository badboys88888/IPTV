#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
config.json 驱动的 IPTV 源更新脚本（HTTP 探测版）

修复清单：
  1. host 重复拼端口：1.2.3.4:80 + port=80 → 1.2.3.4:80:80
  2. bytes.lower() 报错（Python3 bytes 无此方法）
  3. HTTP_TIMEOUT 从 2s 放宽到 5s
  4. ★ 核心修复：同一输出文件多分组叠加修改
     浙江[A] 改完 zjiptv.m3u 后，浙江[B] 从已改版本继续改，不从原始文件重来
     → USED_HOSTS 保证 [B] 不会复用 [A] 的 host
     → FILE_CACHE 保证 [B] 不会覆盖 [A] 的修改

环境变量: FOFA_KEY
"""

import os, re, json, base64, requests
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

CONFIG_PATH  = os.path.join(os.path.dirname(__file__), "..", "config.json")
THREADS      = 50
HTTP_TIMEOUT = 5
USED_HOSTS   = set()
RAW_CACHE    = {}   # 原始下载文件，key=文件名，始终不变
FILE_CACHE   = {}   # 输出文件当前内容，key=输出路径，随分组处理累积更新


# ─── 基础工具 ────────────────────────────────────────────────────────────────

def load_config():
    if not os.path.exists(CONFIG_PATH):
        raise FileNotFoundError(f"配置文件不存在: {CONFIG_PATH}")
    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        raw = f.read().strip()
    if not raw:
        raise ValueError("config.json 为空")
    config = json.loads(raw)
    for i, g in enumerate(config):
        for field in ["name", "fofa_query", "output_m3u"]:
            if field not in g:
                raise ValueError(f"分组 {i} 缺少必填字段: {field}")
    return config


def load_fofa_key():
    key = os.getenv("FOFA_KEY")
    if not key:
        raise EnvironmentError("FOFA_KEY 环境变量未设置")
    return key


def search_fofa(key, query):
    """
    搜索 FOFA，返回去重的 host 列表。
    修复：host 字段可能已含端口（如 1.2.3.4:8888），不能再拼一次 port。
    """
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
        # ★ 如果 base 已含冒号说明端口已在其中，不再重复拼
        if p and ":" not in base:
            hosts.append(f"{base}:{p}")
        else:
            hosts.append(base)

    seen, uniq = set(), []
    for h in hosts:
        if h not in seen:
            seen.add(h)
            uniq.append(h)
    return uniq


def download_file(repo, filename):
    url = f"https://raw.githubusercontent.com/{repo}/main/{filename}"
    try:
        r = requests.get(url, timeout=15)
        if r.status_code == 200:
            return r.text
    except Exception:
        pass
    return None


def extract_one_udp(text):
    for line in text.splitlines():
        if line.startswith("http") and "/udp/" in line:
            s = line.split("/udp/")[-1].strip()
            if s and not s.startswith("#"):
                return s
    return None


def test_stream_http(host, stream):
    """
    修复：bytes 没有 .lower()，直接用 b"<html" in chunk 判断。
    """
    url = f"http://{host}/udp/{stream}"
    try:
        r = requests.get(url, stream=True, timeout=HTTP_TIMEOUT)
        if r.status_code == 200:
            chunk = r.raw.read(4096)
            if chunk and b"<html" not in chunk[:500]:
                return host
    except Exception:
        pass
    return None


def find_best_host(candidates, test_udp, require_domain, group_name):
    """
    从候选列表中找第一个可用 host。
    - 已被其他分组用过的 host（在 USED_HOSTS 中）跳过
    - require_domain=True：优先测域名，失败再回落 IP
    """
    fresh = [h for h in candidates if h not in USED_HOSTS]
    if not fresh:
        print(f"[{group_name}] 所有候选 host 均已被其他分组占用")
        return None

    def _test_batch(batch, label):
        if not batch:
            return None
        print(f"[{group_name}] {label}，共 {len(batch)} 个...")
        found = None
        with ThreadPoolExecutor(max_workers=THREADS) as ex:
            fut = {ex.submit(test_stream_http, h, test_udp): h for h in batch}
            for f in as_completed(fut):
                if found is None:
                    found = f.result()
        return found

    if require_domain:
        domains = [h for h in fresh if not re.match(r"^\d+\.\d+\.\d+\.\d+", h.split(":")[0])]
        ips     = [h for h in fresh if     re.match(r"^\d+\.\d+\.\d+\.\d+", h.split(":")[0])]
        best = _test_batch(domains, "优先测试域名")
        if not best:
            print(f"[{group_name}] 域名全部不可用，回落到 IP")
            best = _test_batch(ips, "测试 IP")
    else:
        best = _test_batch(fresh, "测试全部候选")

    if best:
        USED_HOSTS.add(best)
        print(f"[{group_name}] ✅ 选定 host: {best}")
    else:
        print(f"[{group_name}] ❌ 未找到可用 host")
    return best


# ─── 文本替换 ────────────────────────────────────────────────────────────────

def replace_in_m3u_group(text, group_name, new_host):
    """只替换 group-title="group_name" 的频道行，其他分组不动"""
    lines = text.splitlines()
    out = []
    i = 0
    while i < len(lines):
        line = lines[i]
        if line.startswith("#EXTINF") and f'group-title="{group_name}"' in line:
            out.append(line)
            if (i + 1 < len(lines)
                    and lines[i + 1].startswith("http")
                    and "/udp/" in lines[i + 1]):
                stream = lines[i + 1].split("/udp/")[-1].strip()
                out.append(f"http://{new_host}/udp/{stream}")
                i += 2
                continue
        out.append(line)
        i += 1
    return "\n".join(out)


def replace_in_txt_genre(text, group_name, new_host):
    """只替换 #genre# 对应分组内的频道行"""
    lines = text.splitlines()
    out = []
    in_grp = False
    for line in lines:
        if group_name in line and "#genre#" in line:
            in_grp = True
            out.append(line)
            continue
        if in_grp and "#genre#" in line:
            in_grp = False
            out.append(line)
            continue
        if in_grp and "," in line:
            name, url = line.split(",", 1)
            if "/udp/" in url:
                stream = url.split("/udp/")[-1].strip()
                out.append(f"{name},http://{new_host}/udp/{stream}")
            else:
                out.append(line)
        else:
            out.append(line)
    return "\n".join(out)


# ─── 分组处理 ────────────────────────────────────────────────────────────────

def process_group(g, fofa_key):
    name           = g["name"]
    test_udp       = g.get("test_udp")
    require_domain = g.get("require_domain", False)
    repo           = g.get("target_repo")
    m3u_file       = g.get("target_m3u")
    txt_file       = g.get("target_txt")
    out_m3u        = g["output_m3u"]
    out_txt        = g.get("output_txt")

    print(f"\n{'='*60}")
    print(f"处理分组: {name}")
    print(f"{'='*60}")

    # 1. FOFA 搜索
    try:
        candidates = search_fofa(fofa_key, g["fofa_query"])
        if not candidates:
            print(f"[{name}] FOFA 未搜到任何 host，跳过")
            return
        print(f"[{name}] 候选 host: {len(candidates)} 个")
    except Exception as e:
        print(f"[{name}] FOFA 搜索失败: {e}")
        return

    # 2. 下载原始文件（同一文件名只下载一次）
    for fname in filter(None, [m3u_file, txt_file]):
        if fname not in RAW_CACHE:
            print(f"[{name}] 下载 {repo}/{fname} ...")
            content = download_file(repo, fname)
            RAW_CACHE[fname] = content or ""
            if not content:
                print(f"[{name}] ⚠️  下载失败: {fname}")

    m3u_raw = RAW_CACHE.get(m3u_file, "") if m3u_file else ""
    txt_raw = RAW_CACHE.get(txt_file, "") if txt_file else ""

    # 3. 确定测试流
    if not test_udp:
        test_udp = extract_one_udp(m3u_raw)
        if not test_udp:
            print(f"[{name}] 无法获取测试流，跳过")
            return
    print(f"[{name}] 测试流: udp/{test_udp}")

    # 4. 找最优 host（USED_HOSTS 全局去重，保证各分组用不同 host）
    best = find_best_host(candidates, test_udp, require_domain, name)
    if not best:
        return

    # 5. ★ 核心修复：叠加修改而非覆盖
    #    FILE_CACHE[out_m3u] 存的是当前最新版本
    #    第一次处理该文件时用原始内容初始化，后续分组在已改版本上继续改
    #    这样 浙江[A] 改 "浙江电信[A]" 分组，浙江[B] 改 "浙江电信[B]" 分组
    #    两次修改都保留在同一文件里
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if m3u_raw:
        current = FILE_CACHE.get(out_m3u, m3u_raw)          # ← 读已改版本
        updated = replace_in_m3u_group(current, name, best)
        updated = re.sub(r"# 更新时间:.*", f"# 更新时间: {ts}", updated)
        FILE_CACHE[out_m3u] = updated                        # ← 写回缓存
        print(f"[{name}] M3U 已更新 -> {out_m3u}")

    if txt_raw and out_txt:
        current = FILE_CACHE.get(out_txt, txt_raw)
        updated = replace_in_txt_genre(current, name, best)
        updated = re.sub(r"# 更新时间:.*", f"# 更新时间: {ts}", updated)
        FILE_CACHE[out_txt] = updated
        print(f"[{name}] TXT 已更新 -> {out_txt}")


# ─── 写出 ────────────────────────────────────────────────────────────────────

def write_all_output():
    for path, content in FILE_CACHE.items():
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        print(f"  已写入: {path}")


# ─── 入口 ────────────────────────────────────────────────────────────────────

def main():
    print(f"=== IPTV 更新开始 {datetime.now():%Y-%m-%d %H:%M:%S} ===")
    try:
        groups   = load_config()
        fofa_key = load_fofa_key()
    except Exception as e:
        print(f"初始化失败: {e}")
        return

    for g in groups:
        try:
            process_group(g, fofa_key)
        except Exception as e:
            print(f"分组 {g.get('name', '?')} 异常: {e}")

    print("\n写入所有输出文件...")
    write_all_output()
    print(f"=== 任务结束 {datetime.now():%Y-%m-%d %H:%M:%S} ===")


if __name__ == "__main__":
    main()
