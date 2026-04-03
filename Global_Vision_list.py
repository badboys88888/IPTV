import json
import subprocess
import os

# ===============================
# 节目分组（播放列表）
# ===============================
GROUPS = {
    "全球大視野": [
        "https://www.youtube.com/playlist?list=PLvHT0yeWYIuDyLVv1yDiIxhtk1ZQ92_RY"
    ],
    "國際直球對決": [
        "https://www.youtube.com/watch?v=L3QdmF68ibk&list=PLvHT0yeWYIuASUZjoW8OXe4e_UkgP7qDU"
    ],
    "新聞大白話": [
        "https://www.youtube.com/watch?v=gXL7xfVhgxU&list=PLh9lJwqeOuvNPqHfKf10o5Ql9M-OEnoLy"
    ],
    "世界財經周報": [
        "https://www.youtube.com/watch?v=b8iJF64rC-k&list=PLyvXVH_86VfblqpVtRq7D9vRyQMl6o2E8"
    ],
    "文茜的世界周報": [
        "https://www.youtube.com/watch?v=denoskP4brc&list=PLyvXVH_86VfZ7g9Xb5SYIVhpO09Pg2zVI"
    ],
    "孤烟暮蝉": [
        "https://www.youtube.com/@guyanmuchan01/videos?view=0&sort=dd&shelf_id=2"
    ]
}

# ===============================
# 直播频道主页或 live
# ===============================
LIVE_CHANNELS = [
    "https://www.youtube.com/@中天電視CtiTv",
    "https://www.youtube.com/watch?v=vr3XyVCR4T0",
    "https://www.youtube.com/@globalnewstw",
    "https://www.youtube.com/@ettv32",
    "https://www.youtube.com/@newsebc",
    "https://www.youtube.com/@FTV_News",
    "https://www.youtube.com/@CtsTw",
    "https://www.youtube.com/@TVBSNEWS02",
    "https://www.youtube.com/@ustv",
    "https://www.youtube.com/@TVBSNEWS01",
    "https://www.youtube.com/@57ETFN",
    "https://www.youtube.com/@setnews",
    "https://www.youtube.com/@TTV_NEWS",
    "https://www.youtube.com/@三立iNEWS",
    "https://www.youtube.com/@twctvnews",
    "https://www.youtube.com/@EFTV01",
    "https://www.youtube.com/@FTVLifeInfo",
    "https://www.youtube.com/@SDTV55ch",
    "https://www.youtube.com/@phoenixtvglobal",
    "https://www.youtube.com/@LiveNow24H",
    "https://www.youtube.com/@mnews-tw",
    "https://www.youtube.com/@channelnewsasia",
    "https://www.youtube.com/@TDM_MACAU",
    "https://www.youtube.com/@ebcCTime",
    "https://www.youtube.com/@DaAiVideo",
    "https://www.youtube.com/@NTDAPTV",
    "https://www.youtube.com/@FTVDRAMA",
    "https://www.youtube.com/@MadeByBilibili",
    "https://www.youtube.com/@CTSSHOW",
    "https://www.youtube.com/@yoyotvebc",
    "https://www.youtube.com/@abcnewsaustralia",
    "https://www.youtube.com/@cnnturk",
    "https://www.youtube.com/@ChannelsTelevision",
    "https://www.youtube.com/@France24_en",
    "https://www.youtube.com/@Halktvkanali",
    "https://www.youtube.com/@trtworld",
    "https://www.youtube.com/@aljazeeraenglish",
    "https://www.youtube.com/@mbn",
    "https://www.youtube.com/@ABCNews",
    "https://www.youtube.com/@animalplanet",
    "https://www.youtube.com/@kbsworldtv",
    "https://www.youtube.com/@sbsnews8",
    "https://www.youtube.com/@euronews",
    "https://www.youtube.com/@ArirangRadioK-Pop",
    "https://www.youtube.com/@KOREAarirangTV",
    "https://www.youtube.com/@business",
    "https://www.youtube.com/@ytndmb",
    "https://www.youtube.com/@thekpop",
    "https://www.youtube.com/@yonhapnewstv23",
    "https://www.youtube.com/@TNN.Online",
    "https://www.youtube.com/@channelA-news",
    "https://www.youtube.com/@CBSNews",
    "https://www.youtube.com/@mirrornow",
    "https://www.youtube.com/@livenowfox",
    "https://www.youtube.com/@thanthitv",
    "https://www.youtube.com/@NBCNews",
    "https://www.youtube.com/@V6NewsTelugu",
    "https://www.youtube.com/@ZeeBusiness",
    "https://www.youtube.com/@geonews",
    "https://www.youtube.com/@MHONESHRADDHA",
    "https://www.youtube.com/@TimesNow",
    "https://www.youtube.com/@AgendaFreeTV",
    "https://www.youtube.com/@NHKWORLDJAPAN",
    "https://www.youtube.com/@tvOneNews",
    "https://www.youtube.com/@tbsnewsdig",
    "https://www.youtube.com/@ANNnewsCH",
    "https://www.youtube.com/@ntv_news"

]

OUTPUT_FILE = "/volume1/web/youtube/Global_Vision/Global_Vision_list.json"

# 用 dict 保证顺序：直播组最前
final_data = {
    "直播": {"所有直播": []},
    "節目": {}
}

# ==================================================
# 1️⃣ 抓直播（参考 channels.txt 方式，主页/streams）
# ==================================================
print("\n=== 开始抓取直播 ===")
all_live_videos = []

for url in LIVE_CHANNELS:
    print(f"🔍 抓取: {url} 或 {url}/streams")
    try:
        # 用 /streams 可以抓到主页所有正在直播
        cmd = [
            "yt-dlp",
            "--dump-json",
            "--flat-playlist",
            "--playlist-end", "10",
            url + "/streams"
        ]

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
        if result.returncode != 0 or not result.stdout.strip():
            print("直播抓取失败:", result.stderr)
            continue

        for line in result.stdout.strip().split("\n"):
            if not line.strip():
                continue
            data = json.loads(line)
            if not data.get("is_live"):
                continue

            vid_id = data.get("id")
            title = data.get("title", url)
            thumbs = data.get("thumbnails")
            thumbnail = thumbs[-1]["url"] if thumbs else ""
            all_live_videos.append({
                "videoId": vid_id,
                "title": title,
                "thumbnail": thumbnail
            })
            print(f"✅ 直播找到: {title}")

    except subprocess.TimeoutExpired:
        print("⏱ Timeout跳过")
    except Exception as e:
        print(f"❌ 抓取出错: {e}")

final_data["直播"]["所有直播"] = all_live_videos

# ==================================================
# 2️⃣ 抓节目播放列表（点播）
# ==================================================
for group_name, urls in GROUPS.items():
    print(f"\n=== 处理节目分组: {group_name} ===")
    videos = []
    seen_ids = set()

    for url in urls:
        cmd = ["yt-dlp", "--flat-playlist", "--playlist-end", "100", "-J", url]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0 or not result.stdout.strip():
            print("抓取失败:", result.stderr)
            continue

        data = json.loads(result.stdout)

        if "entries" not in data:
            video_id = data.get("id")
            title = data.get("title")
            if video_id and title and video_id not in seen_ids:
                videos.append({
                    "videoId": video_id,
                    "title": title,
                    "thumbnail": f"https://i.ytimg.com/vi/{video_id}/hqdefault.jpg"
                })
                seen_ids.add(video_id)
            continue

        for entry in data.get("entries", []):
            video_id = entry.get("id")
            title = entry.get("title")
            if not video_id or not title:
                continue
            if "Private video" in title or "Deleted video" in title:
                continue
            if video_id in seen_ids:
                continue
            videos.append({
                "videoId": video_id,
                "title": title,
                "thumbnail": f"https://i.ytimg.com/vi/{video_id}/hqdefault.jpg"
            })
            seen_ids.add(video_id)

    final_data["節目"][group_name] = videos

# ==================================================
# 输出 JSON
# ==================================================
with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
    json.dump(final_data, f, indent=2, ensure_ascii=False)

print("\n✅ 全部完成，JSON 已生成")
