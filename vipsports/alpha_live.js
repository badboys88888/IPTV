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
                        m3uContent += `#EXTINF:-1 tvg-logo="${match.home_team_logo}" group-title="Live_API", ${match.event_name} (${stream.source_name})\n`;
                        m3uContent += `#KODIPROP:inputstream.adaptive.license_type=clearkey\n`;
                        m3uContent += `#KODIPROP:inputstream.adaptive.license_key=${stream.manifest_keys}\n`;
                        m3uContent += `${stream.stream_url}\n\n`;
                    }
                });
            });
            console.log("✅ JSON 数据抓取成功");
        } catch (e) { console.error(`❌ JSON 抓取失败: ${url}`); }
    }

    // --- 任务 2: 处理 Telegram (使用 RSS 代理绕过封锁) ---
    console.log(`📡 正在通过 RSS 代理抓取电报: @${TG_CHANNEL}...`);
    try {
        // 使用公开代理接口，GitHub 访问这个地址非常稳定
        const rssUrl = `https://rsshub.app{TG_CHANNEL}`;
        const tgRes = await fetch(rssUrl);
        const xmlText = await tgRes.text();
        
        // 按照项目分割消息
        const items = xmlText.split('<item>');
        let tgCount = 0;

        for (let i = 1; i < items.length; i++) {
            const item = items[i];
            
            // 提取 MPD 链接
            const mpdMatch = item.match(/https?:\/\/[^"'\s\<\>\[\]]+\.mpd[^"'\s\<\>\[\]]*/i);
            // 提取 ClearKey
            const keyMatch = item.match(/[a-fA-F0-9]{32}\s?:\s?[a-fA-F0-9]{32}/i);
            
            if (mpdMatch && keyMatch) {
                const finalUrl = mpdMatch[0].replace(/&amp;/g, '&');
                const finalKey = keyMatch[0].replace(/\s/g, '');

                // 提取标题
                let title = "FIFA+ Stream";
                const titleMatch = item.match(/<title><!\[CDATA\[(.*?)\]\]><\/title>/i);
                if (titleMatch) {
                    // 清理可能存在的 HTML 标签并截取前 50 个字作为标题
                    title = titleMatch[1].replace(/<[^>]*>/g, '').trim().substring(0, 50);
                }

                m3uContent += `#EXTINF:-1 group-title="FIFA+_Updates", [TG] ${title}\n`;
                m3uContent += `#KODIPROP:inputstream.adaptive.license_type=clearkey\n`;
                m3uContent += `#KODIPROP:inputstream.adaptive.manifest_type=mpd\n`;
                m3uContent += `#KODIPROP:inputstream.adaptive.license_key=${finalKey}\n`;
                m3uContent += `${finalUrl}\n\n`;
                
                tgCount++;
                if (tgCount >= 15) break; 
            }
        }
        console.log(`✅ 电报数据抓取成功，共 ${tgCount} 条`);
    } catch (e) { 
        console.error("❌ Telegram RSS 抓取失败:", e.message); 
    }

    // --- 保存文件 ---
    fs.writeFileSync('live.m3u', m3uContent);
    console.log("🎉 全部数据已合并至 live.m3u，请在根目录查看。");
}

run();
