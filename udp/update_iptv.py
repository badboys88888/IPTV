#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
config.json 驱动的 IPTV 源更新脚本
读取 ../config.json，使用 foFa.icu API 搜索每组指定主机，
从目标仓库拉取 M3U/TXT 文件，提取现有 UDP 流地址，
通过并发测试找到可用 IP，替换并推送回对应仓库。

环境变量：
  FOFA_KEY      foFa.icu 的 API Key
  GH_TOKEN      GitHub Personal Access Token (需有目标仓库写入权限)
"""

import os
import re
import json
import base64
import requests
import cv2
import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# ── 配置 ──────────────────────────────────────────────
CONFIG_PATH   = os.path.join(os.path.dirname(__file__), "..", "config.json")
THREADS       = 20          # 并发测试线程数
TEST_TIMEOUT  = 5           # 流测试超时(秒)
MIN_CHANNELS  = 0           # 最低频道数过滤，暂不使用
# ──────────────────────────────────────────────────────

# 全局去重集合，避免同一 IP 被多个分组重复使用
USED_HOSTS = set()

# ────────────────── 工具函数 ──────────────────────────

def load_config():
    """加载 config.json"""
    if not os.path.exists(CONFIG_PATH):
        raise FileNotFoundError(f"配置文件不存在: {CONFIG_PATH}")
    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        config = json.load(f)
    if not isinstance(config, list):
        raise ValueError("config.json 应为一个数组")
    return config


def load_env_token(name):
    """读取环境变量并检查"""
    token = os.getenv(name)
    if not token:
        raise EnvironmentError(f"缺少环境变量: {name}")
    return token


def search_fofa_icu(key, query):
    """调用 fofa.icu API 搜索主机，返回去重后的 host:port 列表"""
    q_b64 = base64.b64encode(query.encode()).decode()
    params = {
        "key": key,
        "qbase64": q_b64,
        "fields": "host,ip,port",
        "page": 1,
        "size": 10000,          # 一次性取足够多
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


def extract_udp_streams(m3u_content):
    """
    从 M3U 内容中提取所有 /udp/xxx 流地址
    返回 [(stream, line_index?), ...] 简单起见只返回流列表
    """
    streams = set()
    lines = m3u_content.splitlines()
    for line in lines:
        if line.startswith("http") and "/udp/" in line:
            stream = line.split("/udp/")[-1].strip()
            if stream and not stream.startswith("#"):
                streams.add(stream)
    return list(streams)


def test_stream(host, stream):
    """
    测试单个 host 是否可以播放指定的 UDP 流
    stream 格式: "233.50.201.118:5140"
    返回 host 如果成功，否则 None
    """
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


def find_best_host(candidates, streams, require_domain=False, group_name=""):
    """
    从 candidates 中并发测试 streams，找到第一个能用的 host。
    如果 require_domain 为 True，则仅返回域名类型的 host（非纯 IP）。
    排除全局已使用的 host。
    """
    global USED_HOSTS
    # 过滤掉已使用的
    fresh = [h for h in candidates if h not in USED_HOSTS]
    if not fresh:
        print(f"[{group_name}] 无未使用的候选 host，跳过")
        return None

    best = None
    print(f"[{group_name}] 开始测试 {len(fresh)} 个候选 host...")

    with ThreadPoolExecutor(max_workers=THREADS) as executor:
        futures = {}
        for host in fresh:
            for stream in streams:
                futures[executor.submit(test_stream, host, stream)] = (host, stream)

        for future in as_completed(futures):
            res = future.result()
            if res:
                host = res
                # 检查域名要求
                if require_domain:
                    # 简单判断：包含字母且至少有一个点，非纯 IP
                    if re.match(r'\d+\.\d+\.\d+\.\d+', host.split(":")[0]):
                        continue   # 是 IP，但要求域名，跳过
                # 找到可用，记录并返回
                USED_HOSTS.add(host)
                print(f"[{group_name}] 选定可用 host: {host}")
                return host
    print(f"[{group_name}] 未找到满足要求的 host")
    return None


def replace_in_txt(txt_content, group_name, new_host):
    """在 TXT 格式内容中替换指定分组内的主机地址"""
    lines = txt_content.splitlines()
    new_lines = []
    in_group = False
    for line in lines:
        if group_name in line and "#genre#" in line:
            in_group = True
            new_lines.append(line)
            continue
        if in_group and "#genre#" in line:
            in_group = False

        if in_group and "," in line:
            name, old_url = line.split(",", 1)
            stream = old_url.split("/udp/")[-1].strip()
            new_lines.append(f"{name},http://{new_host}/udp/{stream}")
        else:
            new_lines.append(line)
    return "\n".join(new_lines)


def replace_in_m3u(m3u_content, group_name, new_host):
    """在 M3U 格式内容中替换指定分组内的主机地址"""
    lines = m3u_content.splitlines()
    new_lines = []
    in_group = False
    for line in lines:
        if "#EXTINF" in line and group_name in line:
            in_group = True
            new_lines.append(line)
            continue
        if in_group and line.startswith("http"):
            stream = line.split("/udp/")[-1].strip()
            new_lines.append(f"http://{new_host}/udp/{stream}")
            in_group = False
        else:
            new_lines.append(line)
    return "\n".join(new_lines)


def push_to_github(repo, file_name, content, token):
    """通过 GitHub API 更新文件内容"""
    url = f"https://api.github.com/repos/{repo}/contents/{file_name}"
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "iptv-updater"
    }
    # 获取当前文件的 sha
    resp = requests.get(url, headers=headers, timeout=15)
    if resp.status_code != 200:
        print(f"  ⚠️  获取 {repo}/{file_name} 失败: {resp.status_code} {resp.text[:200]}")
        return False
    sha = resp.json().get("sha")
    if not sha:
        print(f"  ⚠️  未找到 sha，可能文件不存在")
        return False

    # 提交更新
    data = {
        "message": f"Update {file_name} ({datetime.now().strftime('%Y-%m-%d %H:%M')})",
        "content": base64.b64encode(content.encode("utf-8")).decode("utf-8"),
        "sha": sha,
    }
    put_resp = requests.put(url, headers=headers, json=data, timeout=15)
    if put_resp.status_code in [200, 201]:
        print(f"  ✅ 推送成功: {repo}/{file_name}")
        return True
    else:
        print(f"  ❌ 推送失败: {put_resp.status_code} {put_resp.text[:200]}")
        return False


def process_group(group, fofa_key, gh_token):
    """处理单个分组：搜索、测试、替换、推送"""
    name = group["name"]
    repo = group["target_repo"]
    txt_file = group.get("target_txt")
    m3u_file = group.get("target_m3u")
    require_domain = group.get("require_domain", False)
    query = group["fofa_query"]

    if not txt_file or not m3u_file:
        print(f"[{name}] 未指定目标文件，跳过")
        return

    print(f"\n{'='*60}\n处理分组: {name}\n{'='*60}")

    # 1. FOFA 搜索
    try:
        print(f"[{name}] 搜索 FOFA: {query[:60]}...")
        candidates = search_fofa_icu(fofa_key, query)
        if not candidates:
            print(f"[{name}] 未搜到任何 host")
            return
        print(f"[{name}] 获得 {len(candidates)} 个候选 host")
    except Exception as e:
        print(f"[{name}] FOFA 搜索失败: {e}")
        return

    # 2. 获取目标文件的原始内容
    base_url = f"https://raw.githubusercontent.com/{repo}/main"
    try:
        print(f"[{name}] 下载目标文件...")
        m3u_resp = requests.get(f"{base_url}/{m3u_file}", timeout=15)
        if m3u_resp.status_code != 200:
            print(f"[{name}] 无法下载 {m3u_file}: HTTP {m3u_resp.status_code}")
            return
        m3u_content = m3u_resp.text

        txt_content = ""
        if txt_file:
            txt_resp = requests.get(f"{base_url}/{txt_file}", timeout=15)
            if txt_resp.status_code == 200:
                txt_content = txt_resp.text
            else:
                print(f"[{name}] 无法下载 {txt_file}，将跳过 TXT 更新")
    except Exception as e:
        print(f"[{name}] 下载失败: {e}")
        return

    # 3. 提取需要测试的 UDP 流
    streams = extract_udp_streams(m3u_content)
    if not streams:
        print(f"[{name}] 目标 M3U 中没有找到 UDP 流，跳过")
        return
    print(f"[{name}] 待测试 UDP 流: {len(streams)} 个")

    # 4. 寻找最佳 host
    best_host = find_best_host(candidates, streams, require_domain, group_name=name)
    if not best_host:
        return

    # 5. 替换内容
    print(f"[{name}] 更新文件内容...")
    m3u_new = replace_in_m3u(m3u_content, name, best_host)
    update_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    m3u_new = re.sub(r"# 更新时间:.*", f"# 更新时间: {update_time}", m3u_new)

    txt_new = None
    if txt_content:
        txt_new = replace_in_txt(txt_content, name, best_host)
        txt_new = re.sub(r"# 更新时间:.*", f"# 更新时间: {update_time}", txt_new)

    # 6. 推送更新
    print(f"[{name}] 推送更新到 {repo}...")
    push_to_github(repo, m3u_file, m3u_new, gh_token)
    if txt_new:
        push_to_github(repo, txt_file, txt_new, gh_token)

    print(f"[{name}] 分组处理完成。\n")


def main():
    print(f"=== IPTV 源更新任务开始: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ===")

    # 加载配置和环境变量
    try:
        groups = load_config()
        fofa_key = load_env_token("FOFA_KEY")
        gh_token = load_env_token("GH_TOKEN")
    except Exception as e:
        print(f"初始化失败: {e}")
        return

    # 依次处理每个分组
    for group in groups:
        try:
            process_group(group, fofa_key, gh_token)
        except Exception as e:
            print(f"分组 [{group.get('name', 'unknown')}] 发生未捕获异常: {e}")

    print(f"\n=== 任务结束: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ===")


if __name__ == "__main__":
    main()
