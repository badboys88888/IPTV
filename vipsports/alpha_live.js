const fs = require('fs');

// 【重要】在这里填入你想要采集的所有 JSON 原始链接 (Raw URL)
const JSON_SOURCES = [
    "https://raw.githubusercontent.com/srhady/vipsports/refs/heads/main/alpha_live.json", // 示例1
    "https://githubusercontent.com" // 示例2（如有更多请继续添加）
];

async function fetchAndConvert() {
    let m3uHeader = "#EXTM3U\n#EXT-X-SESSION-DATA:ID=\"SOURCE\",VALUE=\"AutoBot\"\n\n";
    let m3uBody = "";

    for (const url of JSON_SOURCES) {
        try {
            console.log(`正在获取: ${url}`);
            const response = await fetch(url);
            if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
            const data = await response.json();

            // 提取 live_matches (针对你提供的这种格式)
            const matches = data.live_matches || [];

            matches.forEach(match => {
                if (!match.streams) return;

                match.streams.forEach(stream => {
                    // 只处理有实际链接的
                    if (stream.stream_url && stream.stream_url.startsWith('http')) {
                        const title = `${match.event_name} (${stream.source_name || 'Live'})`;
                        const logo = match.home_team_logo || "";
                        const group = match.category || "Sports";
                        const key = stream.manifest_keys || "";

                        m3uBody += `#EXTINF:-1 tvg-logo="${logo}" group-title="${group}", ${title}\n`;
                        
                        // 如果有解密 Key，添加 ClearKey 属性
                        if (key && key.includes(':')) {
                            m3uBody += `#KODIPROP:inputstream.adaptive.license_type=clearkey\n`;
                            m3uBody += `#KODIPROP:inputstream.adaptive.license_key=${key}\n`;
                        }
                        
                        m3uBody += `${stream.stream_url}\n\n`;
                    }
                });
            });
        } catch (error) {
            console.error(`无法处理链接 ${url}:`, error.message);
        }
    }

    if (m3uBody === "") {
        console.log("警告：未发现任何正在直播的链接。");
    }

    fs.writeFileSync('live.m3u', m3uHeader + m3uBody);
    console.log("✅ 成功生成 live.m3u");
}

fetchAndConvert();
