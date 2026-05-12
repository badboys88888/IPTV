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

    // --- 任务 2: 抓取 Telegram (RSS 模式，绕过 IP 屏蔽) ---
    try {
        console.log(`📡 正在通过 RSS 接口抓取电报频道: @${TG_CHANNEL}`);
        
        // 使用公开的 RSS 代理获取频道内容
        const rssUrl = `https://rsshub.app{TG_CHANNEL}`;
        
        const tgRes = await fetch(rssUrl, {
            headers: {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
        });

        if (!tgRes.ok) throw new Error(`RSS 访问失败: ${tgRes.status}`);
        
        const xmlText = await tgRes.text();
        
        // 匹配 RSS 里的内容块
        const items = xmlText.split('<item>');
        let tgCount = 0;

        for (let i = 1; i < items.length; i++) {
            const item = items[i];
            
            // 在描述标签 <description> 中寻找 MPD 和 Key
            const mpdMatch = item.match(/https?:\/\/[^"'\s\<\>\[\]]+\.mpd[^"'\s\<\>\[\]]*/i);
            const keyMatch = item.match(/[a-fA-F0-9]{32}\s?:\s?[a-fA-F0-9]{32}/i);
            
            if (mpdMatch) {
                const finalKey = keyMatch ? keyMatch.replace(/\s/g, '') : null;
                const finalUrl = mpdMatch[0].replace(/&amp;/g, '&').replace(/<!\[CDATA\[/g, '').replace(/\]\]>/g, '');

                // 提取标题
                let title = "FIFA+ Stream";
                const titleMatch = item.match(/<title><!\[CDATA\[(.*?)\]\]><\/title>/i);
                if (titleMatch) title = titleMatch[1].trim();

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
        console.log(`✅ RSS 抓取成功，新增 ${tgCount} 个频道`);
    } catch (e) {
        console.error("❌ Telegram RSS 抓取出错:", e.message);
        console.log("💡 提示：如果此接口也失效，可能需要配置电报 Bot 或私有 Proxy。");
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
