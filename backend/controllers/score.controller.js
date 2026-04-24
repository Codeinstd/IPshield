/**
 * score.controller.js
 * Place in: backend/controllers/score.controller.js
 */

const { getFullIntel }    = require("../services/ipintel.service");
const { alertIfCritical } = require("../services/alerts.service");
const { addAudit }        = require("../store/memory.store");
const db                  = require("../store/db");
const logger              = require("../utils/logger");

exports.scoreIP = async (req, res, next) => {
  try {
    const { ip } = req.params;
    logger.info(`Scoring IP: ${ip}`);

    const result = await getFullIntel(ip);

    addAudit(result);
    db.insertScore(result);

    // Fire-and-forget alert — never blocks response
    alertIfCritical(result).catch(() => {});

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