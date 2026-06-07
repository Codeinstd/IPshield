const { getFullIntel }    = require("../services/ipIntel.service");
const { alertIfCritical } = require("../services/alerts.service");
const { sendToSIEM }      = require("../services/siem.service");
const { addAudit }        = require("../store/memory.store");
const db                  = require("../store/db");
const logger              = require("../utils/logger");

// constants 

const DEFAULT_SEVERITY_MAP = {
  CRITICAL: 90,
  HIGH:     75,
  MEDIUM:   50,
  LOW:      25,
};

const MAX_IPS = 200;

// helpers 

/**
 * Derive blacklist severity from a numeric score using the severity map.
 * Returns the highest severity whose threshold the score meets.
 */
function severityFromScore(score, severityMap) {
  if (score >= severityMap.CRITICAL) return "CRITICAL";
  if (score >= severityMap.HIGH)     return "HIGH";
  if (score >= severityMap.MEDIUM)   return "MEDIUM";
  return "LOW";
}

/**
 * Write one row to audit_log. Silently swallowed on failure — same pattern
 * as the existing scoreIP and scoreBatch controllers.
 */
async function persistAudit(result) {
  try {
    await db.query(
      `INSERT INTO audit_log
         (ip, score, risk_level, action, is_proxy, is_tor, is_datacenter,
          country, isp, asn, cached, scored_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,NOW())`,
      [
        result.ip,
        result.score,
        result.riskLevel,
        result.action                      || null,
        result.intelligence?.isProxy       || false,
        result.intelligence?.isTor         || false,
        result.intelligence?.isDatacenter  || false,
        result.geo?.country                || null,
        result.network?.isp                || null,
        result.network?.asn                || null,
        result.meta?.cached                || false,
      ]
    );
  } catch (err) {
    logger.error("batch-and-block audit_log insert error:", err.message);
  }
}

/**
 * Check whether the IP already has an active blacklist entry.
 * Returns the row or null.
 */
async function getActiveBlacklistEntry(ip) {
  try {
    const { rows } = await db.query(
      `SELECT * FROM blacklist
       WHERE ip = $1
         AND (expires_at IS NULL OR expires_at > NOW())
       LIMIT 1`,
      [ip]
    );
    return rows[0] || null;
  } catch {
    return null;
  }
}

/**
 * Insert a new blacklist row and return it.
 * Returns null if the insert fails (e.g. concurrent insert race — 409 is fine).
 */
async function insertBlacklist({ ip, severity, reason, added_by, tags, expires_at }) {
  try {
    const { rows } = await db.query(
      `INSERT INTO blacklist (ip, severity, category, reason, added_by, tags, expires_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7)
       ON CONFLICT (ip) DO NOTHING
       RETURNING *`,
      [
        ip,
        severity,
        "auto-block",
        reason     || `Auto-blocked by batch-and-block (score threshold)`,
        added_by   || "batch-and-block",
        tags       || [],
        expires_at || null,
      ]
    );
    return rows[0] || null;
  } catch (err) {
    logger.error("batch-and-block blacklist insert error:", err.message);
    return null;
  }
}

// controller 

exports.scoreBatchAndBlock = async (req, res, next) => {
  try {
    const {
      ips,
      auto_block_threshold = 75,
      dry_run              = false,
      severity_map,
      tags       = [],
      added_by   = "batch-and-block",
      expires_at = null,
    } = req.body;

    // Merge caller's severity overrides over the defaults
    const resolvedSeverityMap = { ...DEFAULT_SEVERITY_MAP, ...severity_map };

    // Deduplicate while preserving order
    const uniqueIPs = [...new Set(ips)];

    logger.info(
      `batch-and-block: ${uniqueIPs.length} IPs, threshold=${auto_block_threshold}, dry_run=${dry_run}`
    );

    // 1. Score all IPs in parallel
    const settled = await Promise.allSettled(uniqueIPs.map(ip => getFullIntel(ip)));

    // 2. Process results 
    const blocked = [];
    const allowed = [];
    const failed  = [];

    await Promise.all(
      settled.map(async (outcome, idx) => {
        const ip = uniqueIPs[idx];

        // Scoring hard-failed
        if (outcome.status === "rejected") {
          failed.push({ ip, error: outcome.reason?.message || "Scoring failed" });
          return;
        }

        const result = outcome.value;

        // Attach existing blacklist status (mirrors scoreIP behaviour)
        const existingEntry = await getActiveBlacklistEntry(ip);
        result.blacklisted = existingEntry
          ? {
              id:         existingEntry.id,
              severity:   existingEntry.severity,
              category:   existingEntry.category   || null,
              reason:     existingEntry.reason      || null,
              added_by:   existingEntry.added_by    || null,
              added_at:   existingEntry.added_at    || null,
              expires_at: existingEntry.expires_at  || null,
              tags:       Array.isArray(existingEntry.tags) ? existingEntry.tags : [],
            }
          : null;

        // Audit + side-effects (fire-and-forget, same as existing controllers)
        await persistAudit(result);
        addAudit(result);
        alertIfCritical(result).catch(() => {});
        sendToSIEM(result).catch(() => {});

        // Decision: should this IP be blocked? 
        const meetsThreshold = result.score >= auto_block_threshold;
        const alreadyBlocked = !!result.blacklisted;

        if (meetsThreshold && !alreadyBlocked) {
          const severity    = severityFromScore(result.score, resolvedSeverityMap);
          let blacklistEntry = null;

          if (!dry_run) {
            blacklistEntry = await insertBlacklist({
              ip,
              severity,
              reason:     `Score ${result.score} — ${result.riskLevel}`,
              added_by,
              tags,
              expires_at,
            });
          } else {
            // Synthetic plan entry so callers can inspect what would happen
            blacklistEntry = {
              ip,
              severity,
              category:   "auto-block",
              reason:     `[dry-run] Score ${result.score} — ${result.riskLevel}`,
              added_by,
              tags,
              expires_at,
              dry_run:    true,
            };
          }

          blocked.push({ ...result, blacklist_entry: blacklistEntry });
        } else {
          // Already blocked or below threshold — land in allowed with context
          allowed.push({
            ...result,
            _skip_reason: alreadyBlocked
              ? "already_blacklisted"
              : "below_threshold",
          });
        }
      })
    );

    // 3. Respond 207 
    return res.status(207).json({
      summary: {
        total:         uniqueIPs.length,
        scored:        blocked.length + allowed.length,
        blocked:       blocked.length,
        allowed:       allowed.length,
        failed:        failed.length,
        dry_run:       !!dry_run,
        threshold:     auto_block_threshold,
      },
      blocked,
      allowed,
      failed,
    });
  } catch (err) {
    next(err);
  }
};