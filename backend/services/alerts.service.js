const axios = require("axios");

const THRESHOLD = parseInt(process.env.ALERT_THRESHOLD || "80");

async function alertIfCritical(result) {
  if (result.score < THRESHOLD) return;

  const riskColor = { CRITICAL: "#FF3355", HIGH: "#FF7700", MEDIUM: "#FFCC00", LOW: "#00E87C" };
  const color     = riskColor[result.riskLevel] || "#00D9FF";
  const geo       = result.geo || {};
  const intel     = result.intelligence || {};

  const flags = [
    intel.isTor        && "Tor Exit Node",
    intel.isProxy      && "Proxy",
    intel.isDatacenter && "Datacenter",
    intel.vulns?.length && `⚠ ${intel.vulns.length} CVEs`,
  ].filter(Boolean).join(" · ") || "None";

  // ── Slack 
  if (process.env.SLACK_WEBHOOK) {
    try {
      await axios.post(process.env.SLACK_WEBHOOK, {
        attachments: [{
          color,
          title: `🚨 ${result.riskLevel} IP Detected: ${result.ip}`,
          fields: [
            { title: "Score",    value: `${result.score}/100`,                    short: true },
            { title: "Action",   value: result.action,                             short: true },
            { title: "Location", value: `${geo.city || "—"}, ${geo.country || "—"}`, short: true },
            { title: "ISP",      value: result.network?.isp || "—",               short: true },
            { title: "Flags",    value: flags,                                     short: false }
          ],
          footer: "IPShield · Risk Intelligence",
          ts:     Math.floor(Date.now() / 1000)
        }]
      }, { timeout: 5000 });
    } catch (err) {
      console.error("Slack alert failed:", err.message);
    }
  }

  // ── Discord 
  if (process.env.DISCORD_WEBHOOK) {
    try {
      await axios.post(process.env.DISCORD_WEBHOOK, {
        embeds: [{
          title:       `🚨 ${result.riskLevel} IP: ${result.ip}`,
          color:       parseInt(color.replace("#", ""), 16),
          description: `**Score:** ${result.score}/100 · **Action:** ${result.action}`,
          fields: [
            { name: "Location", value: `${geo.city || "—"}, ${geo.country || "—"}`, inline: true },
            { name: "ISP",      value: result.network?.isp || "—",                  inline: true },
            { name: "Flags",    value: flags,                                        inline: false }
          ],
          footer:    { text: "IPShield · Risk Intelligence" },
          timestamp: new Date().toISOString()
        }]
      }, { timeout: 5000 });
    } catch (err) {
      console.error("Discord alert failed:", err.message);
    }
  }
}

module.exports = { alertIfCritical };