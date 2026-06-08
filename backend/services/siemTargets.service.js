
const axios  = require("axios");
const db     = require("../store/db");
const logger = require("../utils/logger");

// Reuse the payload builders from your existing siem.service.js
const {
  buildGenericPayload,
} = require("./siem.service");

// Local payload builders (same as siem.service.js, reused here) 
const RISK_ORDER = { LOW: 0, MEDIUM: 1, HIGH: 2, CRITICAL: 3 };

function meetsTargetThreshold(result, target) {
  if (result.score < target.min_score) return false;
  if ((RISK_ORDER[result.riskLevel] ?? 0) < (RISK_ORDER[target.min_risk] ?? 0)) return false;
  return true;
}

function buildPayload(type, result) {

  // Import builders inline to avoid circular deps
  const siem = require("./siem.service");
  switch (type) {
    case "splunk":   return { payload: siem.buildSplunkPayload?.(result)   || buildGenericPayload(result), contentType: "application/json",  auth: (token) => ({ Authorization: `Splunk ${token}` }) };
    case "elastic":  return { payload: siem.buildElasticPayload?.(result)  || buildGenericPayload(result), contentType: "application/json",  auth: (token) => ({ Authorization: `ApiKey ${token}` }) };
    case "sentinel": return { payload: [siem.buildSentinelPayload?.(result) || buildGenericPayload(result)], contentType: "application/json", auth: (token) => ({ "Log-Type": "IPShield", Authorization: `SharedKey ${token}` }) };
    case "qradar":   return { payload: siem.buildQRadarPayload?.(result)   || buildGenericPayload(result),  contentType: "text/plain",        auth: (token) => ({ SEC: token }) };
    default:         return { payload: buildGenericPayload(result),                                          contentType: "application/json",  auth: (token) => token ? { Authorization: `Bearer ${token}` } : {} };
  }
}

// Fan-out to all enabled DB targets 

async function sendToAllSIEMTargets(result) {
  let targets;
  try {
    const res = await db.query(
      `SELECT * FROM siem_targets WHERE enabled = TRUE`
    );
    targets = res.rows;
  } catch (err) {
    logger.error("[siemTargets] Failed to load targets:", err.message);
    return [];
  }

  if (!targets.length) return [];

  const results = await Promise.allSettled(
    targets
      .filter(t => meetsTargetThreshold(result, t))
      .map(t => sendToTarget(t, result))
  );

  return results.map((r, i) => ({
    targetId:   targets[i]?.id,
    targetName: targets[i]?.name,
    success:    r.status === "fulfilled" && r.value?.sent,
    error:      r.status === "rejected" ? r.reason?.message : r.value?.reason,
  }));
}

async function sendToTarget(target, result) {
  const { payload, contentType, auth } = buildPayload(target.type, result);
  const headers = {
    "Content-Type": contentType,
    ...(target.token ? auth(target.token) : {}),
  };

  try {
    const res = await axios.post(target.url, payload, {
      headers,
      timeout:        5000,
      validateStatus: s => s < 500,
      httpsAgent:     target.verify_ssl
        ? undefined
        : new (require("https").Agent)({ rejectUnauthorized: false }),
    });

    const sent = res.status < 400;

    // Update last_sent / last_error
    await db.query(
      `UPDATE siem_targets
       SET last_sent = NOW(), last_error = $1
       WHERE id = $2`,
      [sent ? null : `HTTP ${res.status}`, target.id]
    ).catch(() => {});

    if (!sent) logger.warn(`[siemTargets] ${target.name} returned ${res.status}`);
    else logger.info(`[siemTargets] ${target.name}: forwarded ${result.ip}`);

    return { sent, status: res.status };
  } catch (err) {
    await db.query(
      `UPDATE siem_targets SET last_error = $1 WHERE id = $2`,
      [err.message, target.id]
    ).catch(() => {});
    logger.error(`[siemTargets] ${target.name} failed:`, err.message);
    return { sent: false, reason: err.message };
  }
}

// CRUD for managing targets 

async function listTargets() {
  const res = await db.query(
    `SELECT id, name, type, url, enabled, min_score, min_risk,
            verify_ssl, created_at, last_sent, last_error,
            CASE WHEN token IS NOT NULL THEN true ELSE false END AS has_token
     FROM siem_targets ORDER BY created_at ASC`
  );
  return res.rows;
}

async function createTarget({ name, type, url, token, enabled = true, minScore = 0, minRisk = "LOW", verifySsl = true }) {
  const res = await db.query(
    `INSERT INTO siem_targets
       (name, type, url, token, enabled, min_score, min_risk, verify_ssl)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
     RETURNING id, name, type, url, enabled, min_score, min_risk, verify_ssl, created_at`,
    [name, type, url, token || null, enabled, minScore, minRisk, verifySsl]
  );
  return res.rows[0];
}

async function updateTarget(id, fields) {
  const allowed = ["name","type","url","token","enabled","min_score","min_risk","verify_ssl"];
  const sets    = [];
  const params  = [];
  let   i       = 1;

  for (const [k, v] of Object.entries(fields)) {
    if (!allowed.includes(k)) continue;
    sets.push(`${k} = $${i++}`);
    params.push(v);
  }
  if (!sets.length) return null;

  params.push(id);
  const res = await db.query(
    `UPDATE siem_targets SET ${sets.join(", ")} WHERE id = $${i} RETURNING *`,
    params
  );
  return res.rows[0] || null;
}

async function deleteTarget(id) {
  const res = await db.query(
    `DELETE FROM siem_targets WHERE id = $1 RETURNING id`,
    [id]
  );
  return res.rows.length > 0;
}

async function testTarget(id) {
  const res = await db.query(`SELECT * FROM siem_targets WHERE id = $1`, [id]);
  if (!res.rows.length) return { success: false, reason: "Target not found" };

  const mockResult = {
    ip: "185.220.101.1", score: 95, baseScore: 85, scoreBoost: 10,
    riskLevel: "CRITICAL", action: "BLOCK",
    geo:          { country: "Germany", city: "Frankfurt" },
    network:      { isp: "Test ISP", asn: "AS60729", type: "hosting" },
    intelligence: { isProxy: false, isTor: true, isDatacenter: true, velocity: "HIGH", openPorts: [80,443], vulns: [], shodanTags: ["tor"] },
    threatFeeds:  { feodo: true, spamhaus: false, emergingThreats: true, otx: { pulseCount: 3 } },
    whois:        { orgName: "Test Org" },
    meta:         { processingMs: 100, cached: false },
  };

  // Temporarily override threshold for test
  const target = { ...res.rows[0], min_score: 0, min_risk: "LOW" };
  const result = await sendToTarget(target, mockResult);
  return { success: result.sent, status: result.status, reason: result.reason };
}

module.exports = {
  sendToAllSIEMTargets,
  listTargets, createTarget, updateTarget, deleteTarget, testTarget,
};