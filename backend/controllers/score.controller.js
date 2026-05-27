const { getFullIntel }    = require("../services/ipIntel.service");
const { alertIfCritical } = require("../services/alerts.service");
const { sendToSIEM }      = require("../services/siem.service");
const { addAudit }        = require("../store/memory.store");
const db                  = require("../store/db");
const logger              = require("../utils/logger");
const { isBlacklisted }   = require("../store/blacklist.store");
const { checkAndAutoCase } = require("../services/autoCase.service");


exports.scoreIP = async (req, res, next) => {
  try {
    const { ip } = req.params;
    logger.info(`Scoring IP: ${ip}`);

    const result = await getFullIntel(ip);

    // Check blacklist via Postgres
    try {
      const blRes = await db.query(
        `SELECT * FROM blacklist
         WHERE ip = $1
           AND (expires_at IS NULL OR expires_at > NOW())
         LIMIT 1`,
        [ip]
      );
      if (blRes.rows.length) {
        const bl = blRes.rows[0];
        result.blacklisted = {
          id:         bl.id,
          severity:   bl.severity,
          category:   bl.category   || null,
          reason:     bl.reason     || null,
          added_by:   bl.added_by   || null,
          added_at:   bl.added_at   || null,
          expires_at: bl.expires_at || null,
          tags:       Array.isArray(bl.tags) ? bl.tags : [],
        };
      } else {
        result.blacklisted = null;
      }
    } catch (_) {
      result.blacklisted = null;
    }

    // Persist to audit_log
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
          result.action      || null,
          result.intelligence?.isProxy      || false,
          result.intelligence?.isTor        || false,
          result.intelligence?.isDatacenter || false,
          result.geo?.country  || null,
          result.network?.isp  || null,
          result.network?.asn  || null,
          result.meta?.cached  || false,
        ]
      );
    } catch (dbErr) {
      logger.error("audit_log insert error:", dbErr.message);
    }

    addAudit(result);
    checkAndAutoCase(result).catch(() => {});
    // Fire-and-forget
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

    const output = await Promise.all(results.map(async (r, i) => {
      if (r.status === "fulfilled") {
        const result = r.value;

        // Persist to audit_log
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
              result.action      || null,
              result.intelligence?.isProxy      || false,
              result.intelligence?.isTor        || false,
              result.intelligence?.isDatacenter || false,
              result.geo?.country  || null,
              result.network?.isp  || null,
              result.network?.asn  || null,
              result.meta?.cached  || false,
            ]
          );
        } catch (_) {}

        addAudit(result);
        checkAndAutoCase(result).catch(() => {});
        alertIfCritical(result).catch(() => {});
        sendToSIEM(result).catch(() => {});
        return result;
      }
      return { ip: ips[i], error: r.reason?.message || "Failed", score: null };
    }));

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