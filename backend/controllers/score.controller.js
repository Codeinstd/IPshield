const { getFullIntel }          = require("../services/ipIntel.service");
const { alertIfCritical }       = require("../services/alerts.service");
const { sendToSIEM }            = require("../services/siem.service");
const { addAudit }              = require("../store/memory.store");
const db                        = require("../store/db");
const logger                    = require("../utils/logger");
const { isBlacklisted }         = require("../store/blacklist.store");
const { checkAndAutoCase }      = require("../services/autoCase.service");
const { detectClusters }        = require("../services/cluster.service");
const { sendToAllSIEMTargets }  = require("../services/siemTargets.service");
const { appendAuditEntry }      = require("../store/auditLog.store");

// Shared: attach blacklist data to a score result 

async function attachBlacklist(result) {
  try {
    const blRes = await db.query(
      `SELECT * FROM blacklist
       WHERE ip = $1
         AND (expires_at IS NULL OR expires_at > NOW())
       LIMIT 1`,
      [result.ip]
    );
    result.blacklisted = blRes.rows.length ? {
      id:         blRes.rows[0].id,
      severity:   blRes.rows[0].severity,
      category:   blRes.rows[0].category   || null,
      reason:     blRes.rows[0].reason     || null,
      added_by:   blRes.rows[0].added_by   || null,
      added_at:   blRes.rows[0].added_at   || null,
      expires_at: blRes.rows[0].expires_at || null,
      tags:       Array.isArray(blRes.rows[0].tags) ? blRes.rows[0].tags : [],
    } : null;
  } catch {
    result.blacklisted = null;
  }
}

// Shared: fire-and-forget side effects after scoring 

function fireSideEffects(result) {
  checkAndAutoCase(result).catch(err =>
    logger.error("[scoreIP] autoCase error:", err.message)
  );
  detectClusters(result).catch(err =>
    logger.error("[scoreIP] cluster error:", err.message)
  );
  sendToAllSIEMTargets(result).catch(err =>
    logger.error("[scoreIP] SIEM targets error:", err.message)
  );
  alertIfCritical(result).catch(err =>
    logger.error("[scoreIP] alert error:", err.message)
  );
  sendToSIEM(result).catch(err =>
    logger.error("[scoreIP] SIEM error:", err.message)
  );
}

// POST /api/score/:ip 

exports.scoreIP = async (req, res, next) => {
  try {
    const { ip } = req.params;
    logger.info(`Scoring IP: ${ip}`);

    const result = await getFullIntel(ip);

    await attachBlacklist(result);

    // Append to immutable audit log — hash chain enforced inside transaction
    await appendAuditEntry(result).catch(err =>
      logger.error("[scoreIP] audit append error:", err.message)
    );

    // In-memory store for session display
    addAudit(result);

    // Fire-and-forget side effects
    fireSideEffects(result);

    res.json(result);

  } catch (err) {
    next(err);
  }
};

// POST /api/score/batch
// Batch scores serially for audit log integrity — parallel hashing
// would cause race conditions in the hash chain even with FOR UPDATE.

exports.scoreBatch = async (req, res, next) => {
  try {
    const { ips } = req.body;
    logger.info(`Batch scoring ${ips.length} IPs`);

    // Score all IPs in parallel (intel fetching is safe to parallelise)
    const intelResults = await Promise.allSettled(
      ips.map(ip => getFullIntel(ip))
    );

    // Attach blacklist data in parallel (read-only, safe)
    await Promise.allSettled(
      intelResults.map(r =>
        r.status === "fulfilled" ? attachBlacklist(r.value) : Promise.resolve()
      )
    );

    // Write audit entries SERIALLY — each must read the previous row's hash
    // before inserting, so parallel writes would corrupt the chain
    const output = [];

    for (let i = 0; i < intelResults.length; i++) {
      const r = intelResults[i];

      if (r.status === "fulfilled") {
        const result = r.value;

        // Serial audit append — preserves hash chain integrity
        await appendAuditEntry(result).catch(err =>
          logger.error(`[scoreBatch] audit append error for ${result.ip}:`, err.message)
        );

        addAudit(result);
        fireSideEffects(result);

        output.push(result);
      } else {
        output.push({
          ip:    ips[i],
          error: r.reason?.message || "Failed",
          score: null,
        });
      }
    }

    res.json({
      total:   output.length,
      scored:  output.filter(r => r.score != null).length,
      failed:  output.filter(r => r.error).length,
      results: output,
    });

  } catch (err) {
    next(err);
  }
};