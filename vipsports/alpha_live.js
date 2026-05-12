const fs = require('fs');

// --- 配置区 ---
const JSON_SOURCES = [
    "https://raw.githubusercontent.com/srhady/vipsports/refs/heads/main/alpha_live.json"
];
const TG_CHANNEL = "afifffff_plus";

async function run() {
    console.log("🚀 启动全量合并抓取任务...");
    let m3uContent = "#EXTM3U\n#EXT-X-SESSION-DATA:ID=\"SOURCE\",VALUE=\"Hady_Combined\"\n\n";
    
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
                        m3uContent += `#EXTINF:-1 tvg-logo="${match.home_team_logo}" group-title="体育直播", ${match.event_name} (${stream.source_name})\n`;
                        m3uContent += `#KODIPROP:inputstream.adaptive.license_type=clearkey\n`;
                        m3uContent += `#KODIPROP:inputstream.adaptive.license_key=${stream.manifest_keys}\n`;
                        m3uContent += `${stream.stream_url}\n\n`;
                    }
                });
            });
            console.log("✅ JSON 数据抓取成功");
        } catch (e) { console.error(`❌ JSON 抓取失败: ${url}`); }
    }

    // --- 任务 2: 处理 Telegram (最终增强版) ---
    console.log(`📡 正在抓取电报频道: @${TG_CHANNEL}...`);
    try {
        const embedUrl = `https://t.me/s/${TG_CHANNEL}`;
        const tgRes = await fetch(embedUrl, {
            headers: {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64 ) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
            }
        });

        if (!tgRes.ok) throw new Error(`访问失败: ${tgRes.status}`);
        let html = await tgRes.text();
        
        // 关键步骤：处理 HTML 转义字符，防止链接中的 & 变成 &amp; 导致播放失败
        html = html.replace(/&amp;/g, '&');
        
        // 使用预览页正确的容器类名分割
        const messages = html.split('tgme_widget_message_wrap');
        let tgCount = 0;

        for (let i = messages.length - 1; i >= 0; i--) {
            const msg = messages[i];
            
            // 匹配 MPD 链接
            const mpdMatch = msg.match(/https?:\/\/[^"'\s<> ]+\.mpd[^"'\s<> ]*/i );
            // 匹配 ClearKey (32位:32位)
            const keyMatch = msg.match(/[a-f0-9]{32}:[a-f0-9]{32}/i);
            
            if (mpdMatch && keyMatch) {
                let title = "FIFA+ Stream";
                const textMatch = msg.match(/<div class="tgme_widget_message_text[^>]*>([\s\S]*?)<\/div>/i);
                if (textMatch) {
                    title = textMatch[1]
                        .replace(/<[^>]*>/g, '') // 移除 HTML 标签
                        .replace(/\s+/g, ' ')    // 合并空格
                        .trim()
                        .substring(0, 80);
                }

                m3uContent += `#EXTINF:-1 group-title="FIFA+_Updates", [TG] ${title}\n`;
                m3uContent += `#KODIPROP:inputstream.adaptive.license_type=clearkey\n`;
                m3uContent += `#KODIPROP:inputstream.adaptive.manifest_type=mpd\n`;
                m3uContent += `#KODIPROP:inputstream.adaptive.license_key=${keyMatch[0]}\n`;
                m3uContent += `${mpdMatch[0]}\n\n`;
                
                tgCount++;
                if (tgCount >= 20) break; 
            }
        }
        console.log(`✅ 电报抓取成功，共找到 ${tgCount} 条有效节目`);
    } catch (e) { 
        console.error("❌ Telegram 抓取失败:", e.message);
    }


    // --- 保存文件 ---
    fs.writeFileSync('live.m3u', m3uContent);
    console.log("🎉 全部数据已合并至 live.m3u，请在根目录查看。");
}

run();
