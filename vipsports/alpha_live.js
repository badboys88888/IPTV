const fs = require('fs');

const JSON_SOURCES = [
    "https://raw.githubusercontent.com/srhady/vipsports/refs/heads/main/alpha_live.json"
];
const TG_CHANNEL = "afifffff_plus";

async function run() {
    console.log("🚀 启动实时合并抓取任务...");
    let m3uContent = "#EXTM3U\n#EXT-X-SESSION-DATA:ID=\"SOURCE\",VALUE=\"Hady_Realtime_Bot\"\n\n";
    
    // --- 任务 1: JSON 抓取 ---
    for (const url of JSON_SOURCES) {
        try {
            const res = await fetch(url + "?t=" + Date.now()); 
            const data = await res.json();
            (data.live_matches || []).forEach(match => {
                (match.streams || []).forEach(stream => {
                    if (stream.stream_url?.startsWith('http')) {
                        // JSON 部分带上 logo
                        const logo = match.home_team_logo || "";
                        m3uContent += `#EXTINF:-1 tvg-logo="${logo}" group-title="实时赛事", ${match.event_name} (${stream.source_name})\n`;
                        m3uContent += `#KODIPROP:inputstream.adaptive.license_type=clearkey\n`;
                        m3uContent += `#KODIPROP:inputstream.adaptive.license_key=${stream.manifest_keys}\n`;
                        m3uContent += `${stream.stream_url}\n\n`;
                    }
                });
            });
        } catch (e) { console.error("❌ JSON抓取失败"); }
    }

 // --- 任务 2: Telegram 实时抓取（增强版，带 tvg-logo 提取）---
let tgSuccess = false;
const tgUrls = [
    `https://t.me/s/${TG_CHANNEL}?before=${Date.now()}`,
    `https://t.me/${TG_CHANNEL}?before=${Date.now()}`,
    `https://telegram.dog/${TG_CHANNEL}?before=${Date.now()}`
];

for (const embedUrl of tgUrls) {
    if (tgSuccess) break;
    try {
        console.log(`📡 尝试抓取: ${embedUrl}`);
        const tgRes = await fetch(embedUrl, {
            headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36' }
        });
        if (!tgRes.ok) continue;
        
        let html = await tgRes.text();
        html = html.replace(/&amp;/g, '&');
        
        // 检查是否被拦截
        if (html.includes('access denied') || html.includes('cf-challenge')) {
            console.log(`⚠️ 被拦截: ${embedUrl}`);
            continue;
        }
        
        const messages = html.split('tgme_widget_message_wrap');
        if (messages.length <= 1) {
            console.log(`⚠️ 未找到消息容器，尝试其他URL`);
            continue;
        }
        
        let tgCount = 0;
        for (let i = messages.length - 1; i >= 0; i--) {
            const msg = messages[i];
            const mpdMatch = msg.match(/https?:\/\/[^"'\s<>]+\.mpd[^"'\s<>]*/i);
            if (!mpdMatch) continue;
            
            const keyMatch = msg.match(/[a-f0-9]{32}:[a-f0-9]{32}/i);
            
            // ----- 新增：提取 tvg-logo -----
            let logoUrl = "";
            // 1. 优先查找 img 标签中的 src（telegram 消息图片通常为 tgme_widget_message_photo）
            const imgMatch = msg.match(/<img[^>]+class="[^"]*tgme_widget_message_photo[^"]*"[^>]+src="([^"]+)"/i);
            if (imgMatch && imgMatch[1]) {
                logoUrl = imgMatch[1];
            }
            // 2. 如果没有，尝试背景图片 background-image:url(...)
            if (!logoUrl) {
                const bgMatch = msg.match(/background-image:\s*url\(['"]?([^'"()]+)['"]?\)/i);
                if (bgMatch && bgMatch[1]) logoUrl = bgMatch[1];
            }
            // 3. 再尝试任意 img 标签的 src
            if (!logoUrl) {
                const anyImgMatch = msg.match(/<img[^>]+src="([^"]+)"/i);
                if (anyImgMatch && anyImgMatch[1]) logoUrl = anyImgMatch[1];
            }
            // 4. 若仍没有，尝试链接预览中的图片
            if (!logoUrl) {
                const linkImgMatch = msg.match(/<a[^>]+class="[^"]*link_preview[^"]*"[^>]*>.*?<img[^>]+src="([^"]+)"/is);
                if (linkImgMatch && linkImgMatch[1]) logoUrl = linkImgMatch[1];
            }
            
            // 可选：过滤过期消息
            let timeTag = "";
            const timeMatch = msg.match(/datetime="([^"]+)"/);
            if (timeMatch) {
                const msgTime = new Date(timeMatch[1]);
                const diffHours = (new Date() - msgTime) / 36e5;
                if (diffHours > 48) continue; // 跳过超过48小时的
                if (diffHours < 1) timeTag = "[刚刚]";
            }
            
            let title = "FIFA+ Stream";
            const textMatch = msg.match(/<div class="tgme_widget_message_text[^>]*>([\s\S]*?)<\/div>/i);
            if (textMatch) {
                title = textMatch[1].replace(/<[^>]*>/g, '').trim().substring(0, 80);
            }
            
            // 构建 EXTINF 行，加入 tvg-logo（如果有）
            let extinfLine = `#EXTINF:-1 group-title="TG_Update"`;
            if (logoUrl) {
                extinfLine += ` tvg-logo="${logoUrl}"`;
            }
            extinfLine += `, ${timeTag} ${title}\n`;
            m3uContent += extinfLine;
            
            if (keyMatch) {
                m3uContent += `#KODIPROP:inputstream.adaptive.license_type=clearkey\n`;
                m3uContent += `#KODIPROP:inputstream.adaptive.license_key=${keyMatch[0]}\n`;
            }
            m3uContent += `#KODIPROP:inputstream.adaptive.manifest_type=mpd\n`;
            m3uContent += `${mpdMatch[0]}\n\n`;
            
            tgCount++;
            if (tgCount >= 20) break;
        }
        
        if (tgCount > 0) {
            console.log(`✅ 从 ${embedUrl} 抓取成功，共 ${tgCount} 条`);
            tgSuccess = true;
        } else {
            console.log(`⚠️ ${embedUrl} 未发现有效流，可能是消息缺少mpd或key`);
        }
    } catch (e) {
        console.log(`❌ ${embedUrl} 出错: ${e.message}`);
    }
}

if (!tgSuccess) {
    console.log("❗所有 Telegram 源均抓取失败，请检查频道是否有效或网络环境");
}
    fs.writeFileSync('live.m3u', m3uContent);
    console.log("🎉 live.m3u 已更新！");
}

run();
