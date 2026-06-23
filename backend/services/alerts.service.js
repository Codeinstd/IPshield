const axios = require("axios");
const crypto = require("crypto");
const { sendAlertEmail } = require("./email.service");
const THRESHOLD = Number(process.env.ALERT_THRESHOLD || 80);

const RISK_COLORS = {
  CRITICAL: "#FF3355",
  HIGH: "#FF7700",
  MEDIUM: "#FFCC00",
  LOW: "#00E87C",
};

const VALID_RISK_LEVELS = [
  "LOW",
  "MEDIUM",
  "HIGH",
  "CRITICAL",
];

const http = axios.create({
  timeout: 5000,
});

const alertCache = new Map();

function shouldSuppressAlert(key, ttlMs = 60 * 60 * 1000) {
  const now = Date.now();
  const existing = alertCache.get(key);
  if (existing && existing > now) {
    return true;
  }
  alertCache.set(key, now + ttlMs);
  return false;
}

function truncate(value, max = 500) {
  if (!value) return "";
  const str = String(value);
  return str.length > max ? str.slice(0, max) + "..." : str;
}

function validateAlertPayload(payload) {
  if (!payload) {
    throw new Error("Alert payload missing");
  }
  if (!payload.riskLevel) {
    throw new Error("riskLevel missing");
  }
  if (!VALID_RISK_LEVELS.includes(payload.riskLevel)) {
    throw new Error(`Invalid risk level: ${payload.riskLevel}`);
  }
  return payload;
}

function generateAlertId() {
  return crypto.randomUUID();
}

async function sendSlackAlert(payload) {
  const webhookUrl = process.env.SLACK_WEBHOOK || process.env.SLACK_WEBHOOK_URL;
  if (!webhookUrl) {
    return { skipped: true, reason: "SLACK_WEBHOOK not configured" };
  }

  const { alertId, title, message, ip, score, riskLevel, caseId, type, color, fields } = payload;

  const attachment = {
    color: color || RISK_COLORS[riskLevel] || "#00D9FF",
    title: truncate(title || `🚨 ${riskLevel} IP Detected: ${ip}`, 200),
    fields: fields || [
      ip && { title: "IP", value: truncate(ip, 100), short: true },
      score !== undefined && { title: "Score", value: `${score}/100`, short: true },
      riskLevel && { title: "Risk Level", value: riskLevel, short: true },
      caseId && { title: "Case", value: `#${caseId}`, short: true },
      type && { title: "Type", value: truncate(type, 100), short: true },
      message && { title: "Details", value: truncate(message, 500), short: false },
    ].filter(Boolean),
    footer: `IPShield · Alert ${alertId}`,
    ts: Math.floor(Date.now() / 1000),
  };

  await http.post(webhookUrl, { attachments: [attachment] });
  return { delivered: true, channel: "slack" };
}

async function sendDiscordAlert(payload) {
  const webhook = process.env.DISCORD_WEBHOOK;
  if (!webhook) {
    return { skipped: true, reason: "DISCORD_WEBHOOK not configured" };
  }

  const { alertId, title, message, ip, score, riskLevel, caseId, type, color } = payload;

  const embedColor = parseInt((color || RISK_COLORS[riskLevel] || "#00D9FF").replace("#", ""), 16);

  await http.post(webhook, {
    embeds: [{
      title: truncate(title || `🚨 ${riskLevel} IP: ${ip}`, 256),
      color: embedColor,
      description: truncate(message || `Score: ${score}/100 · Risk: ${riskLevel}`, 4000),
      fields: [
        ip && { name: "IP", value: truncate(ip, 200), inline: true },
        caseId && { name: "Case", value: `#${caseId}`, inline: true },
        type && { name: "Type", value: truncate(type, 500), inline: false },
      ].filter(Boolean),
      footer: { text: `IPShield · Alert ${alertId}` },
      timestamp: new Date().toISOString(),
    }],
  });

  return { delivered: true, channel: "discord" };
}

async function alertIfCritical(result) {
  if (!result) {
    return;
  }
  if (result.score < THRESHOLD) {
    return;
  }

  validateAlertPayload(result);

  const dedupKey = `${result.ip}:${result.riskLevel}`;
  if (shouldSuppressAlert(dedupKey)) {
    console.log(`[ALERT] Suppressed duplicate ${dedupKey}`);
    return;
  }

  const alertId = generateAlertId();
  const geo = result.geo || {};
  const intel = result.intelligence || {};

  const flags = [
    intel.isTor && "Tor Exit Node",
    intel.isProxy && "Proxy",
    intel.isDatacenter && "Datacenter",
    intel.vulns?.length && `${intel.vulns.length} CVEs`,
  ].filter(Boolean).join(" · ") || "None";

  const locationStr = `${geo.city || "—"}, ${geo.country || "—"}`;
  const ispStr       = result.network?.isp || "—";

  const payload = {
    alertId,
    title: `🚨 ${result.riskLevel} IP Detected: ${result.ip}`,
    ip: result.ip,
    score: result.score,
    riskLevel: result.riskLevel,
    color: RISK_COLORS[result.riskLevel],
    message:
      `Action: ${result.action}\n` +
      `Location: ${locationStr}\n` +
      `ISP: ${ispStr}\n` +
      `Flags: ${flags}`,
  };

  const results = await Promise.allSettled([
    sendSlackAlert(payload),
    sendDiscordAlert(payload),
    sendAlertEmail({
      title: payload.title,
      ip: payload.ip,
      score: payload.score,
      riskLevel: payload.riskLevel,
      type: "SCORE_ALERT",
      action: result.action,
      location: locationStr,
      isp: ispStr,
      flags,
    }).then(res => ({ ...res, channel: "email" })),
  ]);

  console.log(`[ALERT ${alertId}]`, JSON.stringify(results, null, 2));
  return results;
}

async function sendAlert(payload) {
  validateAlertPayload(payload);
  const alertId = payload.alertId || generateAlertId();
  const enrichedPayload = { ...payload, alertId };

  const results = await Promise.allSettled([
    sendSlackAlert(enrichedPayload),
    sendDiscordAlert(enrichedPayload),
    sendAlertEmail(enrichedPayload).then(result => ({ ...result, channel: "email" })),
  ]);

  const delivered = results
    .filter(r => r.status === "fulfilled" && r.value?.delivered)
    .map(r => r.value.channel);

  const errors = results
    .filter(r => r.status === "rejected")
    .map(r => r.reason?.message);

  if (errors.length) {
    console.error(`[ALERT ${alertId}] errors`, errors);
  }

  return { alertId, delivered, errors };
}

module.exports = {
  alertIfCritical,
  sendAlert,
  sendSlackAlert,
  sendDiscordAlert,
};