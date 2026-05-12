const fs = require('fs');

// --- 配置区 ---
const JSON_SOURCES = [
    "https://raw.githubusercontent.com/srhady/vipsports/refs/heads/main/alpha_live.json"
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

    // --- 任务 2: 抓取 Telegram (增强版：绕过 IP 屏蔽) ---
    try {
        console.log(`📡 正在通过代理抓取电报频道: @${TG_CHANNEL}`);
        
        // 使用 Google Translate 作为代理来访问 Telegram，防止 GitHub IP 被封
        const proxyUrl = `https://google.com{TG_CHANNEL}`;
        
        const tgRes = await fetch(proxyUrl, {
            headers: {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
            }
        });

        if (!tgRes.ok) throw new Error(`代理访问被拒绝: ${tgRes.status}`);
        
        const html = await tgRes.text();
        
        // 在 Google 代理页面中，原始的 HTML 会被包装，我们依旧尝试查找消息块
        if (html.includes('tgme_widget_message_wrap') || html.includes('tgme_widget_message')) {
            // 兼容代理后的 HTML 分割
            const messages = html.split(/tgme_widget_message_wrap|tgme_widget_message/);
            let tgCount = 0;
            
            for (let i = messages.length - 1; i >= 0; i--) {
                const msg = messages[i];
                
                // 更加宽松的 MPD 匹配 (处理可能被转义的字符)
                const mpdMatch = msg.match(/https?:\/\/[^"'\s\<\> ]+\.mpd[^"'\s\<\> ]*/i);
                // 更加宽松的 Key 匹配
                const keyMatch = msg.match(/[a-fA-F0-9]{32}\s?:\s?[a-fA-F0-9]{32}/i);
                
                if (mpdMatch) {
                    const finalKey = keyMatch ? keyMatch[0].replace(/\s/g, '') : null;
                    const finalUrl = mpdMatch[0].replace(/&amp;/g, '&'); // 修复转义字符

                    let title = "FIFA+ Stream";
                    // 尝试抓取标题
                    const bMatch = msg.match(/<b>(.*?)<\/b>/i);
                    if (bMatch) title = bMatch[1].replace(/<[^>]*>/g, '').trim();

                    allChannels.push({
                        title: `[TG] ${title}`,
                        logo: "",
                        group: "Telegram_Update",
                        url: finalUrl,
                        key: finalKey,
                        isFifa: true
                    });
                    tgCount++;
                    if (tgCount >= 15) break;
                }
            }
            console.log(`✅ 电报抓取成功，新增 ${tgCount} 个频道`);
        } else {
            console.log("⚠️ 代理抓取成功但未发现消息内容，可能需要换代理。");
        }
    } catch (e) {
        console.error("❌ Telegram 代理抓取出错:", e.message);
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
