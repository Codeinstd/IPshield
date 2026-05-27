
const axios      = require("axios");
const nodemailer = require("nodemailer");

const THRESHOLD = parseInt(process.env.ALERT_THRESHOLD || "80");

// ── Slack ─────────────────────────────────────────────────────────────────────

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

// ── Discord ───────────────────────────────────────────────────────────────────

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

// ── Email ─────────────────────────────────────────────────────────────────────

let _transporter = null;

function getTransporter() {
  if (_transporter) return _transporter;
  if (!process.env.SMTP_HOST || !process.env.SMTP_USER) return null;

  _transporter = nodemailer.createTransport({
    host:   process.env.SMTP_HOST,
    port:   parseInt(process.env.SMTP_PORT || "587"),
    secure: process.env.SMTP_PORT === "465",
    auth: {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASS,
    },
  });

  return _transporter;
}

async function sendEmailAlert({ title, message, ip, score, riskLevel, caseId, type, details }) {
  const t = getTransporter();
  if (!t) return { skipped: true, reason: "SMTP not configured" };

  const to   = process.env.ALERT_TO;
  const from = process.env.ALERT_FROM || process.env.SMTP_USER;
  if (!to) return { skipped: true, reason: "ALERT_TO not set" };

  const riskColors = { CRITICAL: "#ff3355", HIGH: "#ff7700", MEDIUM: "#ffcc00", LOW: "#00e87c" };
  const riskColor  = riskColors[riskLevel] || "#6a8fa8";

  const html = `
<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"></head>
<body style="margin:0;padding:0;background:#0d1117;font-family:'Courier New',monospace;">
  <div style="max-width:600px;margin:0 auto;padding:32px 24px;">
    <div style="border-left:4px solid ${riskColor};padding:20px 24px;background:#111820;border-radius:8px;margin-bottom:24px;">
      <div style="font-size:11px;color:#4a6278;letter-spacing:2px;text-transform:uppercase;margin-bottom:8px;">IPShield Alert</div>
      <div style="font-size:20px;font-weight:700;color:#c9d8e8;margin-bottom:4px;">${title || `${riskLevel} IP Detected`}</div>
      ${message ? `<div style="font-size:13px;color:#8fa8bc;margin-top:8px;">${message}</div>` : ""}
    </div>
    <table style="width:100%;border-collapse:collapse;background:#111820;border-radius:8px;overflow:hidden;">
      ${ip        ? `<tr><td style="padding:10px 16px;color:#4a6278;font-size:11px;border-bottom:1px solid #1e2d3d;">IP ADDRESS</td><td style="padding:10px 16px;color:#00d9ff;font-size:13px;border-bottom:1px solid #1e2d3d;">${ip}</td></tr>` : ""}
      ${score     ? `<tr><td style="padding:10px 16px;color:#4a6278;font-size:11px;border-bottom:1px solid #1e2d3d;">RISK SCORE</td><td style="padding:10px 16px;color:${riskColor};font-weight:700;font-size:13px;border-bottom:1px solid #1e2d3d;">${score}/100</td></tr>` : ""}
      ${riskLevel ? `<tr><td style="padding:10px 16px;color:#4a6278;font-size:11px;border-bottom:1px solid #1e2d3d;">RISK LEVEL</td><td style="padding:10px 16px;font-weight:700;font-size:13px;border-bottom:1px solid #1e2d3d;color:${riskColor};">${riskLevel}</td></tr>` : ""}
      ${caseId    ? `<tr><td style="padding:10px 16px;color:#4a6278;font-size:11px;border-bottom:1px solid #1e2d3d;">CASE</td><td style="padding:10px 16px;color:#c9d8e8;font-size:13px;border-bottom:1px solid #1e2d3d;">#${caseId}</td></tr>` : ""}
      ${type      ? `<tr><td style="padding:10px 16px;color:#4a6278;font-size:11px;">ALERT TYPE</td><td style="padding:10px 16px;color:#c9d8e8;font-size:13px;">${type}</td></tr>` : ""}
    </table>
    ${details ? `<div style="margin-top:16px;padding:16px;background:#0d1117;border:1px solid #1e2d3d;border-radius:8px;font-size:11px;color:#4a6278;font-family:'Courier New',monospace;white-space:pre-wrap;">${JSON.stringify(details, null, 2)}</div>` : ""}
    <div style="margin-top:24px;text-align:center;">
      <a href="https://ipshield.live" style="display:inline-block;padding:10px 24px;background:#00d9ff;color:#000;font-weight:700;text-decoration:none;border-radius:6px;font-size:12px;">
        VIEW IN IPSHIELD →
      </a>
    </div>
    <div style="margin-top:24px;text-align:center;font-size:10px;color:#4a6278;">
      IPShield · ${new Date().toISOString()}
    </div>
  </div>
</body>
</html>`;

  await t.sendMail({
    from,
    to,
    subject: `[IPShield] ${riskLevel || "ALERT"}: ${title || ip}`,
    html,
  });

  return { delivered: true, channel: "email" };
}

// ── alertIfCritical — called from score.controller on every score ─────────────
// Preserves your existing behaviour exactly.

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
    sendEmailAlert({
      title:     `${result.riskLevel} IP Detected: ${result.ip}`,
      ip:        result.ip,
      score:     result.score,
      riskLevel: result.riskLevel,
      type:      "SCORE_ALERT",
    }),
  ]);
}

// ── sendAlert — called from BullMQ alert worker ───────────────────────────────

async function sendAlert(payload) {
  const results = await Promise.allSettled([
    sendSlackAlert(payload),
    sendDiscordAlert(payload),
    sendEmailAlert(payload),
  ]);

  const delivered = results
    .filter(r => r.status === "fulfilled" && r.value?.delivered)
    .map(r => r.value.channel);

  const errors = results
    .filter(r => r.status === "rejected")
    .map(r => r.reason?.message);

  if (errors.length) console.error("[alert] Delivery errors:", errors);

  return { delivered, errors };
}

module.exports = { alertIfCritical, sendAlert, sendSlackAlert, sendDiscordAlert, sendEmailAlert };