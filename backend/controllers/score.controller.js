/**
 * score.controller.js
 * Place in: backend/controllers/score.controller.js
 */

const { getFullIntel } = require("../services/ipintel.service");
const { addAudit }     = require("../store/memory.store");
const db               = require("../store/db");

exports.scoreIP = async (req, res, next) => {
  try {
    const { ip } = req.params;
    const result = await getFullIntel(ip);

    // Persist to memory store (audit log)
    addAudit(result);

    // Persist to SQLite if available
    db.insertScore(result);

    res.json(result);
  } catch (err) {
    next(err);
  }
};

// Batch scoring — up to 50 IPs
exports.scoreBatch = async (req, res, next) => {
  try {
    const { ips } = req.body;

    if (!Array.isArray(ips) || ips.length === 0)
      return res.status(400).json({ error: "Provide an array of IPs in body: { ips: [...] }" });

    if (ips.length > 50)
      return res.status(400).json({ error: "Maximum 50 IPs per batch request" });

    const results = await Promise.allSettled(ips.map(ip => getFullIntel(ip)));

    const output = results.map((r, i) => {
      if (r.status === "fulfilled") {
        addAudit(r.value);
        db.insertScore(r.value);
        return r.value;
      }
      return { ip: ips[i], error: r.reason?.message || "Failed", score: null };
    });

    res.json({ total: output.length, results: output });
  } catch (err) {
    next(err);
  }
};