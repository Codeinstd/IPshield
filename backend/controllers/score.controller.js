const { getFullIntel }    = require("../services/ipIntel.service");
const { alertIfCritical } = require("../services/alerts.service");
const { sendToSIEM }      = require("../services/siem.service");
const { addAudit }        = require("../store/memory.store");
const db                  = require("../store/db");
const logger              = require("../utils/logger");
const { isBlacklisted, getDb} = require("../store/blacklist.store");

exports.scoreIP = async (req, res, next) => {
  try {
    const { ip } = req.params;
    logger.info(`Scoring IP: ${ip}`);

    const result = await getFullIntel(ip);

    // Check blacklist
    let blacklistEntry = null;
    try {
      const db = require("../store/db");
      if (db.isAvailable()) {
        blacklistEntry = db.getDb().prepare(
          "SELECT * FROM blacklist WHERE ip = ? AND (expires_at IS NULL OR expires_at > datetime('now')) LIMIT 1"
        ).get(ip);
      }
    } catch (_) {}

    if (blacklistEntry) {
      result.blacklisted = {
        id:        blacklistEntry.id,
        severity:  blacklistEntry.severity,
        category:  blacklistEntry.category  || null,
        reason:    blacklistEntry.reason    || null,
        added_by:  blacklistEntry.added_by  || null,
        added_at:  blacklistEntry.added_at  || null,
        expires_at:blacklistEntry.expires_at|| null,
        tags:      JSON.parse(blacklistEntry.tags || "[]")
      };
    } else {
      result.blacklisted = null;
    }

    addAudit(result);
    db.insertScore(result);

    // Fire-and-forget — never block the response
    alertIfCritical(result).catch(() => {});
    sendToSIEM(result).catch(() => {});

    res.json(result);
  } catch (err) {
    next(err);
  }
};

exports.scoreBatch = async (req, res, next) => {
  try {
    const { ips } = req.body;
    logger.info(`Batch scoring ${ips.length} IPs`);

    const results = await Promise.allSettled(ips.map(ip => getFullIntel(ip)));

    const output = results.map((r, i) => {
      if (r.status === "fulfilled") {
        addAudit(r.value);
        db.insertScore(r.value);
        alertIfCritical(r.value).catch(() => {});
        sendToSIEM(r.value).catch(() => {});
        return r.value;
      }
      return { ip: ips[i], error: r.reason?.message || "Failed", score: null };
    });

    res.json({
      total:   output.length,
      scored:  output.filter(r => r.score != null).length,
      failed:  output.filter(r => r.error).length,
      results: output
    });
  } catch (err) {
    next(err);
  }
};