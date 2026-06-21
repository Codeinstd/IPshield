const crypto = require("crypto");
const db     = require("./db");
const logger = require("../utils/logger");
async function appendAuditEntry(result) {
try {
return await db.transaction(async (client) => {
// Lock last row to prevent race condition in batch scoring
const lastRow = await client.query(
`SELECT row_hash FROM audit_log ORDER BY id DESC LIMIT 1 FOR UPDATE`
      );
const prevHash = lastRow.rows.length
? lastRow.rows[0].row_hash
: "GENESIS";
const scoredAt = new Date().toISOString();
// Deterministic content — same fields always in same order.
// NOTE: confidence/confidence_reasons are intentionally NOT part of this

const content = JSON.stringify({
ip:         result.ip,
score:      result.score,
risk_level: result.riskLevel,
scored_at:  scoredAt,
prev_hash:  prevHash,
      });
const rowHash = crypto
        .createHash("sha256")
        .update(content)
        .digest("hex");
const inserted = await client.query(
`INSERT INTO audit_log (
          ip, score, risk_level, action,
          is_proxy, is_tor, is_dc,
          country, city, isp, asn,
          is_feodo, is_spamhaus, is_et, otx_pulses,
          cached, processing_ms, api_version,
          confidence, confidence_reasons,
          prev_hash, row_hash, scored_at
        ) VALUES (
          $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,
          $12,$13,$14,$15,$16,$17,$18,
          $19,$20,
          $21,$22,NOW()
        ) RETURNING id, row_hash`,
        [
result.ip,
result.score,
result.riskLevel,
result.action                          || null,
result.intelligence?.isProxy           || false,
result.intelligence?.isTor             || false,
result.intelligence?.isDatacenter      || false,
result.geo?.country                    || null,
result.geo?.city                       || null,
result.network?.isp                    || null,
result.network?.asn                    || null,
result.threatFeeds?.feodo              || false,
result.threatFeeds?.spamhaus           || false,
result.threatFeeds?.emergingThreats    || false,
result.threatFeeds?.otx?.pulseCount    || 0,
result.meta?.cached                    || false,
result.meta?.processingMs              || null,
"v2",
result.confidence                      || null,
JSON.stringify(result.confidenceReasons || []),
prevHash,
rowHash,
        ]
      );
logger.info(`[audit] entry #${inserted.rows[0].id} appended — hash: ${rowHash.slice(0, 12)}…`);
return inserted.rows[0];
    });
  } catch (err) {
logger.error("[audit] appendAuditEntry failed:", err.message);
throw err;
  }
}

/**
 * saveAuditLog(db, result)
 *
 * Generic third audit-write entry point, matching the (db, result) shape
 * referenced in score.js but never implemented or called anywhere in the
 * codebase. Built for future routes that need to log a scoring result
 * without each one having to know about appendAuditEntry directly.
 *
 * Deliberately delegates to appendAuditEntry rather than running its own
 * INSERT. The `db` param is accepted for call-site compatibility with the
 * original (db, result) shape, but intentionally unused — appendAuditEntry
 * requires db.transaction() with row-locking (`FOR UPDATE`) to keep the
 * hash chain race-condition-safe under concurrent writes, so any future
 * caller passing a different db/client here would silently bypass that
 * protection. Routing through the one transactional function that already
 * does this correctly means every caller — present or future — lands in
 * the same tamper-evident chain rather than a second, unguarded insert
 * path into the same table.
 *
 * If a real future use case needs a non-chained, fire-and-forget audit
 * write (e.g. something too high-volume for the chain's serial-write
 * requirement), that should be a deliberate, separate decision — not an
 * accidental side door introduced by this function existing.
 */
async function saveAuditLog(db, result) {
  return appendAuditEntry(result);
}

module.exports = { appendAuditEntry, saveAuditLog };