const fs = require('fs');

// --- 配置区 ---
// 1. JSON 组地址 (API)
const JSON_SOURCES = [
    "https://raw.githubusercontent.com/srhady/vipsports/refs/heads/main/alpha_live.json"
];

// 2. Telegram 频道名
const TG_CHANNEL = "afifffff_plus";

async function run() {
    console.log("🚀 启动 Combined VIP 抓取任务...");
    let m3uContent = "#EXTM3U\n#EXT-X-SESSION-DATA:ID=\"SOURCE\",VALUE=\"FIFA_Combined_Bot\"\n\n";
    
    // --- 任务 1: 处理 JSON 组 ---
    console.log("📡 正在获取 JSON 组数据...");
    for (const url of JSON_SOURCES) {
        try {
            const res = await fetch(url);
            const data = await res.json();
            const matches = data.live_matches || [];
            matches.forEach(match => {
                (match.streams || []).forEach(stream => {
                    if (stream.stream_url?.startsWith('http')) {
                        m3uContent += `#EXTINF:-1 tvg-logo="${match.home_team_logo}" group-title="Live_API", ${match.event_name} (${stream.source_name})\n`;
                        m3uContent += `#KODIPROP:inputstream.adaptive.license_type=clearkey\n`;
                        m3uContent += `#KODIPROP:inputstream.adaptive.license_key=${stream.manifest_keys}\n`;
                        m3uContent += `${stream.stream_url}\n\n`;
                    }
                });
            });
        } catch (e) { console.error(`❌ JSON 抓取失败: ${url}`); }
    }

    // --- 任务 2: 处理 Telegram (@afifffff_plus) ---
    console.log(`📡 正在抓取 Telegram 频道: @${TG_CHANNEL}...`);
    try {
        const tgRes = await fetch(`https://t.me{TG_CHANNEL}`);
        const html = await tgRes.text();
        const messages = html.split('<div class="tgme_widget_message_wrap');
        
        let tgCount = 0;
        // 从最新的消息开始往前找
        for (let i = messages.length - 1; i >= 0; i--) {
            const msg = messages[i];
            
            // 匹配 MPD 链接和 ClearKey
            const mpdMatch = msg.match(/https?:\/\/[^"'\s\<\> ]+\.mpd[^"'\s\<\> ]*/i);
            const keyMatch = msg.match(/[a-f0-9]{32}:[a-f0-9]{32}/i);
            
            if (mpdMatch && keyMatch) {
                // 提取标题逻辑：优先寻找加粗文字，并清理 HTML 标签
                const boldMatches = msg.match(/<b>(.*?)<\/b>/g);
                let title = "FIFA+ Stream";
                
                if (boldMatches) {
                    // 通常最后一条加粗包含对阵信息
                    title = boldMatches[boldMatches.length - 1].replace(/<[^>]*>/g, '').trim();
                }

                // 提取日期/时间（如果有）
                const timeInfo = title.match(/\d{2}-\d{2}|\d{2}:\d{2}/g);
                const tag = timeInfo ? `[${timeInfo.join(' ')}]` : "[Live]";

                m3uContent += `#EXTINF:-1 group-title="FIFA+_Updates", ${tag} ${title}\n`;
                m3uContent += `#KODIPROP:inputstream.adaptive.license_type=clearkey\n`;
                // 针对 FIFA+ 的关键参数：强制指定 MPD 类型
                m3uContent += `#KODIPROP:inputstream.adaptive.manifest_type=mpd\n`;
                m3uContent += `#KODIPROP:inputstream.adaptive.license_key=${keyMatch[0]}\n`;
                m3uContent += `${mpdMatch[0]}\n\n`;
                
                tgCount++;
                if (tgCount >= 15) break; // 最多保留最近15个源
            }
        }
        console.log(`✅ 已从电报提取 ${tgCount} 个 FIFA+ 源`);
    } catch (e) { console.error("❌ Telegram 抓取失败:", e.message); }

    // --- 保存文件 ---
    // 生成在当前目录，后续通过 yml 移动到根目录
    fs.writeFileSync('live.m3u', m3uContent);
    console.log("🎉 全部数据已合并至 live.m3u");
}

run();
