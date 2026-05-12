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

        // --- 任务 2: 处理 Telegram (使用官方 Embed 接口，最高成功率) ---
    console.log(`📡 正在通过 Embed 接口抓取电报: @${TG_CHANNEL}...`);
    try {
        // 使用电报官方的嵌入式组件地址，这是目前最稳的抓取路径
        const embedUrl = `https://t.me{TG_CHANNEL}?embed=1&mode=tme`;
        const tgRes = await fetch(embedUrl, {
            headers: {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
            }
        });

        if (!tgRes.ok) throw new Error(`Embed 访问失败: ${tgRes.status}`);
        const html = await tgRes.text();
        
        // 分割单条消息
        const messages = html.split('tgme_widget_message_inline');
        let tgCount = 0;

        for (let i = messages.length - 1; i >= 0; i--) {
            const msg = messages[i];
            
            // 匹配 MPD 和 Key
            const mpdMatch = msg.match(/https?:\/\/[^"'\s\<\> ]+\.mpd[^"'\s\<\> ]*/i);
            const keyMatch = msg.match(/[a-f0-9]{32}:[a-f0-9]{32}/i);
            
            if (mpdMatch && keyMatch) {
                // 提取文字内容作为标题
                let title = "FIFA+ Stream";
                const textMatch = msg.match(/<div class="tgme_widget_message_text[^>]*>([\s\S]*?)<\/div>/i);
                if (textMatch) {
                    title = textMatch[1].replace(/<[^>]*>/g, '').trim().substring(0, 60);
                }

                m3uContent += `#EXTINF:-1 group-title="FIFA+_Updates", [TG] ${title}\n`;
                m3uContent += `#KODIPROP:inputstream.adaptive.license_type=clearkey\n`;
                m3uContent += `#KODIPROP:inputstream.adaptive.manifest_type=mpd\n`;
                m3uContent += `#KODIPROP:inputstream.adaptive.license_key=${keyMatch[0]}\n`;
                m3uContent += `${mpdMatch[0]}\n\n`;
                
                tgCount++;
                if (tgCount >= 15) break; 
            }
        }
        console.log(`✅ 电报 Embed 抓取成功，共 ${tgCount} 条`);
    } catch (e) { 
        console.error("❌ Telegram Embed 抓取失败:", e.message);
        // 如果还不行，输出提示
        console.log("💡 建议：GitHub 官方 IP 可能暂时无法连接 Telegram，请稍后再试或点击 Workflow 再次手动运行。");
    }


    // --- 保存文件 ---
    fs.writeFileSync('live.m3u', m3uContent);
    console.log("🎉 全部数据已合并至 live.m3u，请在根目录查看。");
}

run();
