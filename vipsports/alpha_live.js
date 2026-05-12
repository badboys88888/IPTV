const fs = require('fs');

// --- 配置区 ---
const JSON_SOURCES = [
    "https://raw.githubusercontent.com/srhady/vipsports/refs/heads/main/alpha_live.json" // 请确保这里是完整的 Raw 链接
];

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
        // 【修正点】添加了 /s/ 预览路径和正确的变量引用 $
        const tgRes = await fetch(`https://t.me{TG_CHANNEL}`);
        const html = await tgRes.text();
        
        // 如果 HTML 没内容，说明被屏蔽了
        if (!html.includes('tgme_widget_message_wrap')) {
            throw new Error("未能获取到电报消息内容，页面可能被拦截");
        }

        const messages = html.split('<div class="tgme_widget_message_wrap');
        let tgCount = 0;

        for (let i = messages.length - 1; i >= 0; i--) {
            const msg = messages[i];
            const mpdMatch = msg.match(/https?:\/\/[^"'\s\<\> ]+\.mpd[^"'\s\<\> ]*/i);
            const keyMatch = msg.match(/[a-f0-9]{32}:[a-f0-9]{32}/i);
            
            if (mpdMatch && keyMatch) {
                const boldMatches = msg.match(/<b>(.*?)<\/b>/g);
                let title = "FIFA+ Stream";
                if (boldMatches) {
                    title = boldMatches[boldMatches.length - 1].replace(/<[^>]*>/g, '').trim();
                }

                const timeInfo = title.match(/\d{2}-\d{2}|\d{2}:\d{2}/g);
                const tag = timeInfo ? `[${timeInfo.join(' ')}]` : "[Live]";

                m3uContent += `#EXTINF:-1 group-title="FIFA+_Updates", ${tag} ${title}\n`;
                m3uContent += `#KODIPROP:inputstream.adaptive.license_type=clearkey\n`;
                m3uContent += `#KODIPROP:inputstream.adaptive.manifest_type=mpd\n`;
                // 【修正点】确保取数组的第一个匹配项 [0]
                m3uContent += `#KODIPROP:inputstream.adaptive.license_key=${keyMatch[0]}\n`;
                m3uContent += `${mpdMatch[0]}\n\n`;
                
                tgCount++;
                if (tgCount >= 15) break;
            }
        }
        console.log(`✅ 已从电报提取 ${tgCount} 个 FIFA+ 源`);
    } catch (e) { 
        console.error("❌ Telegram 抓取失败:", e.message); 
    }

    // --- 保存文件 ---
    fs.writeFileSync('live.m3u', m3uContent);
    console.log("🎉 全部数据已合并至 live.m3u");
}

run();
