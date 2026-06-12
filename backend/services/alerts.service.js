
const axios = require("axios");
const { sendAlertEmail } = require("./email.service");

const THRESHOLD = parseInt(process.env.ALERT_THRESHOLD || "80");

// Slack 
async function sendSlackAlert({ title, message, ip, score, riskLevel, caseId, type, color, fields }) {
  const webhookUrl = process.env.SLACK_WEBHOOK || process.env.SLACK_WEBHOOK_URL;
  if (!webhookUrl) return { skipped: true, reason: "SLACK_WEBHOOK not set" };

  const riskColor = { CRITICAL: "#FF3355", HIGH: "#FF7700", MEDIUM: "#FFCC00", LOW: "#00E87C" };
  const c = color || riskColor[riskLevel] || "#00D9FF";

  const attachment = {
    color: c,
    title: title || `🚨 ${riskLevel} IP Detected: ${ip}`,
    fields: fields || [
      ip        && { title: "IP",         value: ip,              short: true },
      score     && { title: "Score",      value: `${score}/100`,  short: true },
      riskLevel && { title: "Risk Level", value: riskLevel,       short: true },
      caseId    && { title: "Case",       value: `#${caseId}`,    short: true },
      type      && { title: "Alert Type", value: type,            short: true },
      message   && { title: "Detail",     value: message,         short: false },
    ].filter(Boolean),
    footer: "IPShield · Risk Intelligence",
    ts:     Math.floor(Date.now() / 1000),
  };

  await axios.post(webhookUrl, { attachments: [attachment] }, { timeout: 5000 });
  return { delivered: true, channel: "slack" };
}

// Discord 
async function sendDiscordAlert({ title, message, ip, score, riskLevel, caseId, type, color }) {
  if (!process.env.DISCORD_WEBHOOK) return { skipped: true, reason: "DISCORD_WEBHOOK not set" };

  const riskColor = { CRITICAL: "#FF3355", HIGH: "#FF7700", MEDIUM: "#FFCC00", LOW: "#00E87C" };
  const c = color || riskColor[riskLevel] || "#00D9FF";

  await axios.post(process.env.DISCORD_WEBHOOK, {
    embeds: [{
      title:       title || `🚨 ${riskLevel} IP: ${ip}`,
      color:       parseInt(c.replace("#", ""), 16),
      description: message || `**Score:** ${score}/100 · **Risk:** ${riskLevel}`,
      fields: [
        ip     && { name: "IP",         value: ip,             inline: true },
        caseId && { name: "Case",       value: `#${caseId}`,   inline: true },
        type   && { name: "Alert Type", value: type,           inline: false },
      ].filter(Boolean),
      footer:    { text: "IPShield · Risk Intelligence" },
      timestamp: new Date().toISOString(),
    }],
  }, { timeout: 5000 });

  return { delivered: true, channel: "discord" };
}

// alertIfCritical — called from score.controller on every score 
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

  const slackFields = [
    { title: "Score",    value: `${result.score}/100`,                       short: true  },
    { title: "Action",   value: result.action,                                short: true  },
    { title: "Location", value: `${geo.city || "—"}, ${geo.country || "—"}`, short: true  },
    { title: "ISP",      value: result.network?.isp || "—",                  short: true  },
    { title: "Flags",    value: flags,                                        short: false },
  ];

  await Promise.allSettled([
    sendSlackAlert({
      title:     `🚨 ${result.riskLevel} IP Detected: ${result.ip}`,
      ip:        result.ip,
      score:     result.score,
      riskLevel: result.riskLevel,
      color,
      fields:    slackFields,
    }),
    sendDiscordAlert({
      title:     `🚨 ${result.riskLevel} IP: ${result.ip}`,
      message:   `**Score:** ${result.score}/100 · **Action:** ${result.action}\n**Location:** ${geo.city || "—"}, ${geo.country || "—"} · **ISP:** ${result.network?.isp || "—"}\n**Flags:** ${flags}`,
      ip:        result.ip,
      score:     result.score,
      riskLevel: result.riskLevel,
      color,
    }),
    sendAlertEmail({
      title:     `${result.riskLevel} IP Detected: ${result.ip}`,
      ip:        result.ip,
      score:     result.score,
      riskLevel: result.riskLevel,
      type:      "SCORE_ALERT",
    }),
  ]);
}

// sendAlert — called from BullMQ alert worker 
async function sendAlert(payload) {
 const results = await Promise.allSettled([
  sendSlackAlert(payload),
  sendDiscordAlert(payload),
  sendAlertEmail(payload),
]);

  const delivered = results
    .filter(r => r.status === "fulfilled" && r.value?.delivered)
    .map(r => r.value.channel);

  const errors = results
    .filter(r => r.status === "rejected")
    .map(r => r.reason?.message);

  console.log("[ALERT RESULTS]", JSON.stringify(results, null, 2));

  return { delivered, errors };
}

module.exports = { alertIfCritical, sendAlert, sendSlackAlert, sendDiscordAlert, sendAlertEmail };