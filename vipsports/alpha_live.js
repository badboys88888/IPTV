const fs = require('fs');

// --- 配置区 ---
const JSON_SOURCES = [
    "https://raw.githubusercontent.com/srhady/vipsports/refs/heads/main/alpha_live.json"
];
const TG_CHANNEL = "afifffff_plus";

async function run() {
    console.log("🚀 启动抓取任务...");
    let m3uContent = "#EXTM3U\n#EXT-X-SESSION-DATA:ID=\"SOURCE\",VALUE=\"Hady_VIP\"\n\n";
    
    // --- 第一部分：严格按照你的 JSON 结构抓取 ---
    console.log("📡 正在处理 JSON 组数据...");
    for (const url of JSON_SOURCES) {
        try {
            const res = await fetch(url);
            const data = await res.json();
            
            // 严格读取 live_matches
            const matches = data.live_matches || [];
            matches.forEach(match => {
                // 遍历该比赛下的 streams 数组
                (match.streams || []).forEach(stream => {
                    const streamUrl = stream.stream_url;
                    
                    // 只有当链接是 http 开头且不是预告文字时才处理
                    if (streamUrl && streamUrl.startsWith('http')) {
                        const title = match.event_name;
                        const category = match.category || "LIVE";
                        const logo = match.home_team_logo || "";
                        const key = stream.manifest_keys;
                        const source = stream.source_name || "Stream";

                        m3uContent += `#EXTINF:-1 tvg-logo="${logo}" group-title="${category}", ${title} (${source})\n`;
                        m3uContent += `#KODIPROP:inputstream.adaptive.license_type=clearkey\n`;
                        
                        // 如果是 mpd 格式，增加 manifest_type 声明
                        if (streamUrl.includes('.mpd')) {
                            m3uContent += `#KODIPROP:inputstream.adaptive.manifest_type=mpd\n`;
                        }
                        
                        // 如果有 key 则写入
                        if (key) {
                            m3uContent += `#KODIPROP:inputstream.adaptive.license_key=${key}\n`;
                        }
                        m3uContent += `${streamUrl}\n\n`;
                    }
                });
            });
            console.log("✅ JSON 数据处理完成");
        } catch (e) { console.error(`❌ JSON 抓取失败: ${url}`); }
    }

    // --- 第二部分：处理 Telegram 频道 ---
    console.log(`📡 正在抓取电报频道: @${TG_CHANNEL}...`);
    try {
        const tgRes = await fetch(`https://t.me{TG_CHANNEL}`, {
            headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36' }
        });
        let html = await tgRes.text();
        html = html.replace(/&amp;/g, '&');
        const messages = html.split('tgme_widget_message_wrap');
        
        let tgCount = 0;
        for (let i = messages.length - 1; i >= 0; i--) {
            const msg = messages[i];
            const mpdMatch = msg.match(/https?:\/\/[^"'\s<> ]+\.mpd[^"'\s<> ]*/i);
            const keyMatch = msg.match(/[a-f0-9]{32}:[a-f0-9]{32}/i);
            
            if (mpdMatch && keyMatch) {
                // 尝试抓取消息图片作为 Logo
                let tgLogo = "https://fifa.com";
                const photoMatch = msg.match(/background-image:url\(['"]?(.*?)['"]?\)/i);
                if (photoMatch) tgLogo = photoMatch[1];

                // 提取标题
                let tgTitle = "FIFA+ Stream";
                const textMatch = msg.match(/<div class="tgme_widget_message_text[^>]*>([\s\S]*?)<\/div>/i);
                if (textMatch) {
                    tgTitle = textMatch[1].replace(/<[^>]*>/g, '').replace(/\s+/g, ' ').trim().substring(0, 80);
                }

                m3uContent += `#EXTINF:-1 tvg-logo="${tgLogo}" group-title="FIFA+_Updates", [TG] ${tgTitle}\n`;
                m3uContent += `#KODIPROP:inputstream.adaptive.license_type=clearkey\n`;
                m3uContent += `#KODIPROP:inputstream.adaptive.manifest_type=mpd\n`;
                m3uContent += `#KODIPROP:inputstream.adaptive.license_key=${keyMatch[0]}\n`;
                m3uContent += `${mpdMatch[0]}\n\n`;
                
                tgCount++;
                if (tgCount >= 15) break; 
            }
        }
        console.log(`✅ 电报抓取成功: ${tgCount} 条`);
    } catch (e) { console.error("❌ Telegram 抓取失败:", e.message); }

    // --- 保存文件 ---
    fs.writeFileSync('live.m3u', m3uContent);
    console.log("🎉 全部数据已合并至 live.m3u");
}

run();
