#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
config.json 驱动的 IPTV 源更新脚本（本地输出版）
仅需环境变量: FOFA_KEY (fofa.icu API key)
"""

import os
import re
import json
import base64
import requests
import cv2
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# ── 配置常量 ─────────────────────────────────────────
CONFIG_PATH   = os.path.join(os.path.dirname(__file__), "..", "config.json")
THREADS       = 50               # 并发测试线程数
TEST_TIMEOUT  = 3                # 流测试超时(秒)
# ──────────────────────────────────────────────────────

USED_HOSTS = set()               # 全局去重（同一 IP 不会被不同分组重复使用）
FILE_CACHE = {}                  # 输出文件内容缓存 {filepath: content}


# ══════════════════ 基础工具 ══════════════════════════

def load_config():
    if not os.path.exists(CONFIG_PATH):
        raise FileNotFoundError(f"配置文件不存在: {CONFIG_PATH}")
    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        raw = f.read().strip()
        if not raw:
            raise ValueError("config.json 是空的")
        config = json.loads(raw)
    for i, g in enumerate(config):
        if "name" not in g or "fofa_query" not in g or "output_m3u" not in g:
            raise ValueError(f"分组 {i} 缺少必填字段: name, fofa_query, output_m3u")
    return config


def load_fofa_key():
    key = os.getenv("FOFA_KEY")
    if not key:
        raise EnvironmentError("环境变量 FOFA_KEY 未设置")
    return key


def search_fofa_icu(key, query):
    """调用 fofa.icu API，返回去重后的 host:port 列表"""
    q_b64 = base64.b64encode(query.encode()).decode()
    params = {
        "key": key,
        "qbase64": q_b64,
        "fields": "host,ip,port",
        "page": 1,
        "size": 10000,
        "full": "false",
    }
    resp = requests.get("https://fofa.icu/api/v1/search/all", params=params, timeout=30)
    resp.raise_for_status()
    data = resp.json()
    if data.get("error"):
        raise RuntimeError(f"FOFA API 错误: {data.get('errmsg', data)}")

    results = data.get("results", [])
    hosts = []
    for r in results:
        if isinstance(r, list):
            host = r[0] if r[0] else r[1]
            port = r[2] if len(r) > 2 and r[2] else ""
            if host:
                entry = f"{host}:{port}" if port else host
                hosts.append(entry)
        elif isinstance(r, str):
            hosts.append(r)
    # 去重保持顺序
    seen = set()
    uniq = []
    for h in hosts:
        if h not in seen:
            seen.add(h)
            uniq.append(h)
    return uniq


def extract_one_udp_stream(m3u_text):
    """从 M3U 文本中提取第一个 UDP 流地址，返回 'ip:port' 部分"""
    for line in m3u_text.splitlines():
        if line.startswith("http") and "/udp/" in line:
            stream = line.split("/udp/")[-1].strip()
            if stream and not stream.startswith("#"):
                return stream
    return None


def test_stream(host, stream):
    """测试单个 host 是否可以播放指定的 UDP 流，成功返回 host，否则 None"""
    try:
        url = f"http://{host}/udp/{stream}"
        cap = cv2.VideoCapture(url)
        cap.set(cv2.CAP_PROP_OPEN_TIMEOUT_MSEC, TEST_TIMEOUT * 1000)
        if cap.isOpened():
            cap.release()
            return host
    except:
        pass
    return None


def find_best_host(candidates, test_udp, require_domain, group_name):
    """从 candidates 中并发测试 test_udp 这一个流，返回第一个可用的 host"""
    global USED_HOSTS
    fresh = [h for h in candidates if h not in USED_HOSTS]
    if not fresh:
        print(f"[{group_name}] 无未使用的候选 host")
        return None

    print(f"[{group_name}] 测试 {len(fresh)} 个候选 host (流: {test_udp})...")
    with ThreadPoolExecutor(max_workers=THREADS) as executor:
        futures = {executor.submit(test_stream, h, test_udp): h for h in fresh}
        for future in as_completed(futures):
            host = future.result()
            if host:
                # 要求域名时跳过纯 IP
                if require_domain and re.match(r'\d+\.\d+\.\d+\.\d+', host.split(":")[0]):
                    continue
                USED_HOSTS.add(host)
                print(f"[{group_name}] 选定可用 host: {host}")
                executor.shutdown(wait=False)   # 找到就取消剩余任务
                return host
    print(f"[{group_name}] 未找到满足要求的 host")
    return None


def download_file(repo, filename):
    """从 GitHub raw 下载文件内容，成功返回文本，失败返回 None"""
    url = f"https://raw.githubusercontent.com/{repo}/main/{filename}"
    try:
        resp = requests.get(url, timeout=15)
        if resp.status_code == 200:
            return resp.text
        else:
            print(f"  下载失败: {url} (HTTP {resp.status_code})")
    except Exception as e:
        print(f"  下载异常: {url} ({e})")
    return None


def load_original_content(repo_filename_pairs):
    """批量下载原始文件，存入全局 FILE_CACHE（仅当缓存中没有时下载）"""
    global FILE_CACHE
    for repo, filename in repo_filename_pairs:
        if filename not in FILE_CACHE:
            print(f"  下载原始文件: {repo}/{filename}")
            content = download_file(repo, filename)
            if content is not None:
                FILE_CACHE[filename] = content
            else:
                # 如果下载失败，设为空字符串，后续写入时可能覆盖，但最好先警告
                print(f"  ⚠️  无法获取 {filename}，将创建新文件")
                FILE_CACHE[filename] = ""


def replace_in_m3u_group(m3u_text, group_name, new_host):
    """
    在 M3U 文本中，将所有 group-title="group_name" 的频道 URL 的 IP 替换为 new_host。
    保留 /udp/ 后面的流地址不变。
    """
    lines = m3u_text.splitlines()
    new_lines = []
    # 标记是否正在处理目标分组 (用于连续频道)
    i = 0
    while i < len(lines):
        line = lines[i]
        # 检查当前行是否为 #EXTINF 且包含目标分组
        if line.startswith("#EXTINF") and f'group-title="{group_name}"' in line:
            new_lines.append(line)          # 保留 EXTINF 行
            # 下一行应该是 URL
            if i + 1 < len(lines):
                url_line = lines[i + 1]
                if url_line.startswith("http") and "/udp/" in url_line:
                    stream = url_line.split("/udp/")[-1].strip()
                    new_url = f"http://{new_host}/udp/{stream}"
                    new_lines.append(new_url)
                    i += 2
                    continue
                else:
                    new_lines.append(url_line)
                    i += 2
                    continue
        else:
            new_lines.append(line)
            i += 1
    return "\n".join(new_lines)


def replace_in_txt_genre(txt_text, group_name, new_host):
    """
    在 TXT 文本中，找到 #genre# 分隔的 group_name 分组，替换该分组下所有频道的 IP。
    TXT 格式示例：
        浙江电信[A] #genre#
        频道1,http://old_ip/udp/stream
        频道2,http://old_ip/udp/stream
    """
    lines = txt_text.splitlines()
    new_lines = []
    in_group = False
    for line in lines:
        if group_name in line and "#genre#" in line:
            in_group = True
            new_lines.append(line)
            continue
        if in_group and "#genre#" in line:   # 遇到下一个 genre 则退出
            in_group = False
            new_lines.append(line)
            continue
        if in_group and "," in line:
            # 频道名,URL 格式
            parts = line.split(",", 1)
            name = parts[0]
            old_url = parts[1]
            if "/udp/" in old_url:
                stream = old_url.split("/udp/")[-1].strip()
                new_lines.append(f"{name},http://{new_host}/udp/{stream}")
            else:
                new_lines.append(line)
        else:
            new_lines.append(line)
    return "\n".join(new_lines)


def update_global_file(filename, new_content):
    """将修改后的内容写回全局缓存（覆盖）"""
    FILE_CACHE[filename] = new_content


def write_all_output():
    """将所有缓存的输出文件写入磁盘"""
    for filepath, content in FILE_CACHE.items():
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content)
        print(f"  写入文件: {filepath}")


# ══════════════════ 分组处理 ══════════════════════════

def process_group(group, fofa_key):
    name = group["name"]
    require_domain = group.get("require_domain", False)
    test_udp = group.get("test_udp")          # 如果配置了就直接用
    target_repo = group.get("target_repo")
    target_m3u = group.get("target_m3u")      # 源 M3U 文件名（从仓库下载）
    target_txt = group.get("target_txt")      # 源 TXT 文件名（可选）
    output_m3u = group["output_m3u"]          # 输出 M3U 路径（本地）
    output_txt = group.get("output_txt")      # 输出 TXT 路径（可选）

    print(f"\n{'='*60}\n处理分组: {name}\n{'='*60}")

    # 1. FOFA 搜索
    try:
        print("搜索 FOFA ...")
        candidates = search_fofa_icu(fofa_key, group["fofa_query"])
        if not candidates:
            print("未搜到任何 host")
            return
        print(f"获得 {len(candidates)} 个候选 host")
    except Exception as e:
        print(f"FOFA 搜索失败: {e}")
        return

    # 2. 确保原始文件已下载到缓存
    #    需要下载的文件：target_m3u 和 target_txt（如果存在）
    dl_list = []
    if target_repo and target_m3u:
        dl_list.append((target_repo, target_m3u))
    if target_repo and target_txt:
        dl_list.append((target_repo, target_txt))
    if dl_list:
        load_original_content(dl_list)

    # 获取缓存中的原始内容
    m3u_content = FILE_CACHE.get(target_m3u, "") if target_m3u else ""
    txt_content = FILE_CACHE.get(target_txt, "") if target_txt else ""

    # 3. 确定测试 UDP 流
    if not test_udp:
        # 从 M3U 中提取第一个流
        test_udp = extract_one_udp_stream(m3u_content)
        if not test_udp:
            print("未配置 test_udp 且无法从 M3U 提取，跳过")
            return
    print(f"测试 UDP 流: {test_udp}")

    # 4. 寻找最佳 host
    best_host = find_best_host(candidates, test_udp, require_domain, name)
    if not best_host:
        return

    # 5. 替换并更新全局缓存
    update_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # 更新 M3U
    if m3u_content:
        new_m3u = replace_in_m3u_group(m3u_content, name, best_host)
        new_m3u = re.sub(r"# 更新时间:.*", f"# 更新时间: {update_time}", new_m3u)
        update_global_file(output_m3u, new_m3u)
        print(f"已更新 M3U 缓存 → {output_m3u}")
    else:
        print(f"⚠️  未获取到 M3U 原始内容，无法更新")

    # 更新 TXT
    if txt_content and output_txt:
        new_txt = replace_in_txt_genre(txt_content, name, best_host)
        new_txt = re.sub(r"# 更新时间:.*", f"# 更新时间: {update_time}", new_txt)
        update_global_file(output_txt, new_txt)
        print(f"已更新 TXT 缓存 → {output_txt}")


# ══════════════════ 主流程 ══════════════════════════

def main():
    print(f"=== IPTV 源更新开始: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ===")

    try:
        groups = load_config()
        fofa_key = load_fofa_key()
    except Exception as e:
        print(f"初始化失败: {e}")
        return

    # 按顺序处理每个分组（后续分组可以复用已下载的原始文件）
    for group in groups:
        try:
            process_group(group, fofa_key)
        except Exception as e:
            print(f"分组 [{group.get('name', 'unknown')}] 异常: {e}")

    # 一次性写入所有输出文件
    print("\n写入所有输出文件...")
    write_all_output()

    print(f"\n=== 任务结束: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ===")


if __name__ == "__main__":
    main()
