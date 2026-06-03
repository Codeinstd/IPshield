const express  = require("express");
const router   = express.Router();

const { scoreBatchAndBlock }              = require("../controllers/scorebatchandblock.controller");
const { scoreIP, scoreBatch }              = require("../controllers/score.controller");
const { validateIPParam, validateBatchBody } = require("../middleware/validateIP.middleware");
const { validateBatchAndBlockBody }        = require("../middleware/validateBatchAndBlockBody.middleware");
const { requireAuth, requireRole }         = require("../middleware/auth.js");


// Existing routes (unchanged)
router.get("/:ip",    requireAuth, requireRole("readonly"), validateIPParam,    scoreIP);
router.post("/batch", requireAuth, requireRole("readonly"), validateBatchBody,  scoreBatch);

//
async function saveAuditLog(db, result) {
  try {
    await db.query(
      `INSERT INTO audit_log (
        ip, score, risk_level, action,
        country, city, isp, asn,
        is_proxy, is_tor, is_dc,
        is_feodo, is_spamhaus, is_et, otx_pulses,
        api_version, cached, processing_ms
      ) VALUES (
        $1,$2,$3,$4,
        $5,$6,$7,$8,
        $9,$10,$11,
        $12,$13,$14,$15,
        $16,$17,$18
      )`,
      [
        result.ip,
        result.score,
        result.riskLevel,
        result.action,
        result.geo?.country      || null,
        result.geo?.city         || null,
        result.network?.isp      || null,
        result.network?.asn      || null,
        result.intelligence?.isProxy      || false,
        result.intelligence?.isTor        || false,
        result.intelligence?.isDatacenter || false,
        result.threatFeeds?.feodo         || false,
        result.threatFeeds?.spamhaus      || false,
        result.threatFeeds?.emergingThreats || false,
        result.threatFeeds?.otx?.pulseCount || 0,
        "v2",
        result.meta?.cached       || false,
        result.meta?.processingMs || null,
      ]
    );
  } catch (err) {
    // Never let audit logging crash a score request
    console.error("[audit] Failed to save:", err.message);
  }
}

// Requires `analyst` role: this endpoint writes to the blacklist.
// Route must be defined BEFORE "/:ip" to avoid Express matching "batch-and-block" as an IP param.
router.post(
  "/batch-and-block",
  requireAuth,
  requireRole("readonly"),
  validateBatchAndBlockBody,
  scoreBatchAndBlock
);

module.exports = router;