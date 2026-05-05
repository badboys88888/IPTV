#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IPTV 源自动更新 (HTTP 探测版, 支持分组叠加修改)

特性:
  - 使用 fofa.icu API 搜索候选 host
  - 仅探测一个测试 UDP 流，第一个可用 host 即被采纳
  - 域名优先 / IP 回退 策略
  - 同一输出文件可被多个分组顺序修改（叠加更新）
  - 全局去重 host，避免不同分组使用相同 IP
  - 下载原始文件仅一次，修改在内存中累积后统一写入
  - 直接生成符合 xteve/udpxy 格式的 M3U/TXT 文件

环境变量: FOFA_KEY (fofa.icu 的 API Key)
"""

import os
import re
import json
import base64
import requests
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# ── 配置常量 ──────────────────────────────────────────
CONFIG_PATH   = os.path.join(os.path.dirname(__file__), "..", "config.json")
THREADS       = 50          # 并发测试线程数
HTTP_TIMEOUT  = 3           # 单次 HTTP 探测超时(秒)
# ──────────────────────────────────────────────────────

USED_HOSTS  = set()        # 全局已用 host
RAW_CACHE   = {}           # 原始下载文件 {文件名: 内容}
FILE_CACHE  = {}           # 输出文件当前累积内容 {输出路径: 内容}


# ══════════════════════════════════════════════════════
#  基础工具
# ══════════════════════════════════════════════════════

def load_config():
    if not os.path.exists(CONFIG_PATH):
        raise FileNotFoundError(f"配置文件不存在: {CONFIG_PATH}")
    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        raw = f.read().strip()
    if not raw:
        raise ValueError("config.json 是空的")
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
    """调用 fofa.icu，返回去重后的 host:port 列表（正确处理端口）"""
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

    results = data.get("results", [])
    hosts = []
    for r in results:
        if not isinstance(r, list):
            continue
        h  = (r[0] or "").strip()
        ip = (r[1] or "").strip()
        p  = str(r[2]).strip() if len(r) > 2 and r[2] else ""
        base = h if h else ip
        if not base:
            continue
        # 如果 base 中已含冒号，说明端口已包含，不再重复
        if p and ":" not in base:
            hosts.append(f"{base}:{p}")
        else:
            hosts.append(base)

    # 去重保序
    seen, uniq = set(), []
    for x in hosts:
        if x not in seen:
            seen.add(x)
            uniq.append(x)
    return uniq


def download_raw(repo, filename):
    """从 GitHub raw 下载文件，失败返回 None"""
    url = f"https://raw.githubusercontent.com/{repo}/main/{filename}"
    try:
        r = requests.get(url, timeout=15)
        return r.text if r.status_code == 200 else None
    except Exception:
        return None


def extract_test_stream(text):
    """从 M3U 文本中提取第一个 /udp/... 流地址，如 '233.50.201.118:5140'"""
    for line in text.splitlines():
        if line.startswith("http") and "/udp/" in line:
            s = line.split("/udp/")[-1].strip()
            if s and not s.startswith("#"):
                return s
    return None


def test_host_http(host, udp_stream):
    """
    快速探测 host 是否可代理 udp 流。
    成功返回 host，否则返回 None。
    """
    url = f"http://{host}/udp/{udp_stream}"
    try:
        r = requests.get(url, stream=True, timeout=HTTP_TIMEOUT)
        if r.status_code == 200:
            chunk = r.raw.read(4096)
            # 排除返回 HTML 错误页的情况
            if chunk and b"<html" not in chunk[:500]:
                return host
    except Exception:
        pass
    return None


# ══════════════════════════════════════════════════════
#  主探测逻辑（找到即停）
# ══════════════════════════════════════════════════════

def find_best_host(candidates, test_udp, require_domain, group_name):
    """
    并发测试候选 host，返回第一个可用的。
    - require_domain: True → 优先域名，失败后回落 IP
    - 已使用的 host 被排除（全局去重）
    """
    fresh = [h for h in candidates if h not in USED_HOSTS]
    if not fresh:
        print(f"[{group_name}] 所有候选 host 均已被占用")
        return None

    def _test_list(hlist, label):
        if not hlist:
            return None
        print(f"[{group_name}] {label}，共 {len(hlist)} 个")
        count = 0
        with ThreadPoolExecutor(max_workers=THREADS) as executor:
            futures = {executor.submit(test_host_http, h, test_udp): h for h in hlist}
            for f in as_completed(futures):
                count += 1
                if count % 30 == 0 or count == 1:
                    print(f"  进度: {count}/{len(hlist)}")
                host = f.result()
                if host:
                    print(f"  在第 {count} 次测试成功！")
                    # 立即终止剩余任务
                    executor.shutdown(wait=False, cancel_futures=True)
                    return host
        return None

    if require_domain:
        domains = [h for h in fresh if not re.match(r"\d+\.\d+\.\d+\.\d+", h.split(":")[0])]
        ips     = [h for h in fresh if re.match(r"\d+\.\d+\.\d+\.\d+", h.split(":")[0])]
        best = _test_list(domains, "优先测试域名")
        if best is None:
            print(f"[{group_name}] 域名均不可用，回落到 IP")
            best = _test_list(ips, "回落测试 IP")
    else:
        best = _test_list(fresh, "测试全部候选")

    if best:
        USED_HOSTS.add(best)
        print(f"[{group_name}] ✅ 选定 host: {best}")
    else:
        print(f"[{group_name}] ❌ 未找到可用 host")
    return best


# ══════════════════════════════════════════════════════
#  文本替换（叠加修改，不覆盖其他分组）
# ══════════════════════════════════════════════════════

def replace_in_m3u(text, group_name, new_host):
    """替换 M3U 中 group-title="group_name" 的所有频道的 IP"""
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
    """替换 TXT 中 #genre# 分组内的所有频道的 IP"""
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


# ══════════════════════════════════════════════════════
#  分组处理
# ══════════════════════════════════════════════════════

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
            print(f"[{name}] 未搜到任何 host")
            return
        print(f"[{name}] 候选 host: {len(candidates)} 个")
    except Exception as e:
        print(f"[{name}] FOFA 搜索失败: {e}")
        return

    # 2. 下载原始文件（同名文件只下载一次）
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
            print(f"[{name}] 无法提取测试流，跳过")
            return
    print(f"[{name}] 测试流: udp/{test_udp}")

    # 4. 探测可用 host
    best = find_best_host(candidates, test_udp, require_domain, name)
    if not best:
        return

    # 5. 叠加修改输出文件
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if m3u_raw:
        cur = FILE_CACHE.get(out_m3u, m3u_raw)   # 之前修改过的版本
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
    """将内存中的输出文件写入磁盘"""
    for path, content in FILE_CACHE.items():
        dirname = os.path.dirname(path) or "."
        os.makedirs(dirname, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        print(f"  已写入: {path}")


# ══════════════════════════════════════════════════════
#  主入口
# ══════════════════════════════════════════════════════

def main():
    print(f"=== IPTV 源更新开始 {datetime.now():%Y-%m-%d %H:%M:%S} ===")
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
    print(f"=== 任务结束 {datetime.now():%Y-%m-%d %H:%M:%S} ===")


if __name__ == "__main__":
    main()
