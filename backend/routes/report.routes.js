
const express       = require("express");
const router        = express.Router();
const rateLimit     = require("express-rate-limit");
const { getFullIntel }    = require("../services/ipIntel.service");
const { generateReport }  = require("../services/report.service");
const { requireAuth }     = require("../middleware/auth.js");
const db                  = require("../store/db");
const logger              = require("../utils/logger");

const reportLimiter = rateLimit({
  windowMs:        60 * 1000,   // 1 minute
  max:             10,
  standardHeaders: true,
  legacyHeaders:   false,
  message:         { error: "Report rate limit reached — try again in 1 minute" },
});

// Validate IP 
function isValidIP(ip) {
  const ipv4 = /^(\d{1,3}\.){3}\d{1,3}$/;
  const ipv6 = /^[0-9a-fA-F:]{2,45}$/;
  return ipv4.test(ip) || ipv6.test(ip);
}

// Attach blacklist data 
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

// GET /api/v2/report/:ip — HTML report 
router.get("/:ip", reportLimiter, async (req, res) => {
  try {
    const ip = decodeURIComponent(req.params.ip).trim();

    if (!isValidIP(ip)) {
      return res.status(400).json({ error: "Invalid IP address" });
    }

    logger.info(`[report/html] Generating report for ${ip}`);

    const scoreResult = await getFullIntel(ip);
    await attachBlacklist(scoreResult);

    const { html } = await generateReport(scoreResult, "html");

    res.setHeader("Content-Type", "text/html; charset=utf-8");
    res.send(html);

  } catch (err) {
    logger.error("[report/html]", err.message);
    res.status(500).json({ error: "Report generation failed", detail: err.message });
  }
});

// GET /api/v2/report/:ip/pdf — PDF download 
router.get("/:ip/pdf", requireAuth, reportLimiter, async (req, res) => {
  try {
    const ip = decodeURIComponent(req.params.ip).trim();

    if (!isValidIP(ip)) {
      return res.status(400).json({ error: "Invalid IP address" });
    }

    logger.info(`[report/pdf] Generating PDF for ${ip}`);

    const scoreResult = await getFullIntel(ip);
    await attachBlacklist(scoreResult);

    const { pdf } = await generateReport(scoreResult, "pdf");

    const filename = `ipshield-report-${ip.replace(/[:.]/g, "-")}-${Date.now()}.pdf`;

    res.setHeader("Content-Type",        "application/pdf");
    res.setHeader("Content-Disposition", `attachment; filename="${filename}"`);
    res.setHeader("Content-Length",      pdf.length);
    res.send(pdf);

  } catch (err) {
    logger.error("[report/pdf]", err.message);
    res.status(500).json({ error: "PDF generation failed", detail: err.message });
  }
});

module.exports = router;