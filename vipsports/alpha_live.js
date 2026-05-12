const fs = require('fs');

const JSON_SOURCES = [
    "https://raw.githubusercontent.com/srhady/vipsports/refs/heads/main/alpha_live.json"
];
const TG_CHANNEL = "afifffff_plus";

async function run() {
    console.log("🚀 启动实时合并抓取任务...");
    let m3uContent = "#EXTM3U\n#EXT-X-SESSION-DATA:ID=\"SOURCE\",VALUE=\"Hady_Realtime_Bot\"\n\n";
    
    // --- 任务 1: JSON 抓取 (保持不变) ---
    for (const url of JSON_SOURCES) {
        try {
            const res = await fetch(url + "?t=" + Date.now()); // 增加随机数防止缓存
            const data = await res.json();
            (data.live_matches || []).forEach(match => {
                (match.streams || []).forEach(stream => {
                    if (stream.stream_url?.startsWith('http')) {
                        m3uContent += `#EXTINF:-1 tvg-logo="${match.home_team_logo}" group-title="API直播", ${match.event_name} (${stream.source_name})\n`;
                        m3uContent += `#KODIPROP:inputstream.adaptive.license_type=clearkey\n`;
                        m3uContent += `#KODIPROP:inputstream.adaptive.license_key=${stream.manifest_keys}\n`;
                        m3uContent += `${stream.stream_url}\n\n`;
                    }
                });
            });
        } catch (e) { console.error("❌ JSON抓取失败"); }
    }

    // --- 任务 2: Telegram 实时抓取 ---
    try {
        // 【关键】增加随机参数防止电报网页版缓存
        const embedUrl = `https://t.me/s/${TG_CHANNEL}?before=${Math.floor(Date.now()/1000)}`;
        console.log(`📡 正在同步电报实时数据...`);
        
        const tgRes = await fetch(embedUrl, {
            headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36' }
        });
        let html = await tgRes.text();
        html = html.replace(/&amp;/g, '&');
        
        const messages = html.split('tgme_widget_message_wrap');
        let tgCount = 0;

        // 电报网页版底部是最新的消息，所以我们从后往前遍历
        for (let i = messages.length - 1; i >= 0; i--) {
            const msg = messages[i];
            
            const mpdMatch = msg.match(/https?:\/\/[^"'\s<> ]+\.mpd[^"'\s<> ]*/i);
            const keyMatch = msg.match(/[a-f0-9]{32}:[a-f0-9]{32}/i);
            
            if (mpdMatch && keyMatch) {
                // 【新增】判断消息时间，过滤掉太旧的消息
                const timeMatch = msg.match(/datetime="([^"]+)"/);
                let timeTag = "[最新]";
                if (timeMatch) {
                    const msgTime = new Date(timeMatch[1]);
                    const diffHours = (new Date() - msgTime) / 1000 / 60 / 60;
                    
                    // 如果消息超过 48 小时，我们标记为 [过期预警] 甚至跳过
                    if (diffHours > 48) continue; 
                    if (diffHours < 1) timeTag = "[刚刚]";
                }

                let title = "FIFA+ Stream";
                const textMatch = msg.match(/<div class="tgme_widget_message_text[^>]*>([\s\S]*?)<\/div>/i);
                if (textMatch) {
                    title = textMatch[1].replace(/<[^>]*>/g, '').trim().substring(0, 80);
                }

                m3uContent += `#EXTINF:-1 group-title="TG_Update", ${timeTag} ${title}\n`;
                m3uContent += `#KODIPROP:inputstream.adaptive.license_type=clearkey\n`;
                m3uContent += `#KODIPROP:inputstream.adaptive.manifest_type=mpd\n`;
                m3uContent += `#KODIPROP:inputstream.adaptive.license_key=${keyMatch[0]}\n`;
                m3uContent += `${mpdMatch[0]}\n\n`;
                
                tgCount++;
                if (tgCount >= 20) break; 
            }
        }
        console.log(`✅ 同步完成，共 ${tgCount} 条实时源`);
    } catch (e) { console.error("❌ TG抓取异常:", e.message); }

    fs.writeFileSync('live.m3u', m3uContent);
    console.log("🎉 live.m3u 已更新！");
}

run();
