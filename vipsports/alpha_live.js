const fs = require('fs');

// --- 配置区 ---
const JSON_SOURCES = [
    "https://githubusercontent.com"
];
const TG_CHANNEL = "afifffff_plus";

async function run() {
    console.log("🚀 开始全量抓取任务...");
    let allChannels = []; // 用来存放所有抓到的频道对象

    // --- 任务 1: 抓取 JSON 组 ---
    for (const url of JSON_SOURCES) {
        try {
            console.log(`📡 正在尝试抓取 JSON: ${url}`);
            const res = await fetch(url);
            if (!res.ok) throw new Error(`HTTP状态码: ${res.status}`);
            const data = await res.json();
            
            const matches = data.live_matches || [];
            matches.forEach(match => {
                (match.streams || []).forEach(stream => {
                    if (stream.stream_url?.startsWith('http')) {
                        allChannels.push({
                            title: `${match.event_name} (${stream.source_name})`,
                            logo: match.home_team_logo || "",
                            group: "FIFA+",
                            url: stream.stream_url,
                            key: stream.manifest_keys
                        });
                    }
                });
            });
            console.log(`✅ JSON 抓取成功，目前总计 ${allChannels.length} 个频道`);
        } catch (e) {
            console.error(`❌ JSON 抓取失败 (${url}):`, e.message);
        }
    }

    // --- 任务 2: 抓取 Telegram ---
    try {
        console.log(`📡 正在抓取电报频道: @${TG_CHANNEL}`);
        const tgRes = await fetch(`https://t.me{TG_CHANNEL}`);
        const html = await tgRes.text();
        const messages = html.split('tgme_widget_message_wrap');
        
        let tgCount = 0;
        for (let i = messages.length - 1; i >= 0; i--) {
            const msg = messages[i];
            const mpdMatch = msg.match(/https?:\/\/[^"'\s\<\> ]+\.mpd[^"'\s\<\> ]*/i);
            const keyMatch = msg.match(/[a-fA-F0-9]{32}\s?:\s?[a-fA-F0-9]{32}/i);
            
            if (mpdMatch) {
                const finalKey = keyMatch ? keyMatch[0].replace(/\s/g, '') : null;
                // 提取标题
                let title = "FIFA+ Stream";
                const bMatch = msg.match(/<b>(.*?)<\/b>/);
                if (bMatch) title = bMatch[1].replace(/<[^>]*>/g, '').trim();

                allChannels.push({
                    title: `[TG] ${title}`,
                    logo: "",
                    group: "Telegram_Update",
                    url: mpdMatch[0],
                    key: finalKey,
                    isFifa: true // 标记一下是 FIFA+ 源
                });
                tgCount++;
                if (tgCount >= 15) break;
            }
        }
        console.log(`✅ 电报抓取成功，新增 ${tgCount} 个频道`);
    } catch (e) {
        console.error("❌ Telegram 抓取出错:", e.message);
    }

    // --- 任务 3: 统一生成 M3U 文件 ---
    let m3uContent = "#EXTM3U\n#EXT-X-SESSION-DATA:ID=\"SOURCE\",VALUE=\"Hady_VIP\"\n\n";
    
    allChannels.forEach(ch => {
        m3uContent += `#EXTINF:-1 tvg-logo="${ch.logo}" group-title="${ch.group}", ${ch.title}\n`;
        m3uContent += `#KODIPROP:inputstream.adaptive.license_type=clearkey\n`;
        // 如果是 FIFA+ 或者 mpd 结尾，加上 manifest_type
        if (ch.isFifa || ch.url.includes('.mpd')) {
            m3uContent += `#KODIPROP:inputstream.adaptive.manifest_type=mpd\n`;
        }
        if (ch.key) {
            m3uContent += `#KODIPROP:inputstream.adaptive.license_key=${ch.key}\n`;
        }
        m3uContent += `${ch.url}\n\n`;
    });

    fs.writeFileSync('live.m3u', m3uContent);
    console.log(`🎉 任务完成！共计生成 ${allChannels.length} 个频道到 live.m3u`);
}

run();
