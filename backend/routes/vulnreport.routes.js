const express                         = require("express");
const router                          = express.Router();
const rateLimit                       = require("express-rate-limit");
const { generateVulnReport }          = require("../services/vulnReport.service");
const { requireAuth, requireRole }    = require("../middleware/auth.js");
const cases                           = require("../store/cases.store.js");   
const scan                            = require("../store/scan.store.js");  
const logger                          = require("../utils/logger");

const reportLimiter = rateLimit({
  windowMs:        60 * 1000,   // 1 minute
  max:             5,           // lower than score report — this is heavier (puppeteer + DB joins)
  standardHeaders: true,
  legacyHeaders:   false,
  message:         { error: "Vulnerability report rate limit reached — try again in 1 minute" },
});

function isValidCaseId(id) {
  return /^\d+$/.test(id);
}

// GET /api/v2/cases/:id/vuln-report — HTML report
router.get("/:id/vuln-report", requireAuth, reportLimiter, async (req, res) => {
  try {
    const caseId = req.params.id;
    if (!isValidCaseId(caseId)) {
      return res.status(400).json({ error: "Invalid case ID" });
    }

    logger.info(`[vuln-report/html] Generating report for case ${caseId}`);
    const { html } = await generateVulnReport(parseInt(caseId, 10), "html", { caseStore, scanStore });

    res.setHeader("Content-Type", "text/html; charset=utf-8");
    res.send(html);
  } catch (err) {
    logger.error("[vuln-report/html]", err.message);
    if (err.message.includes("not found")) {
      return res.status(404).json({ error: "Case not found" });
    }
    res.status(500).json({ error: "Report generation failed", detail: err.message });
  }
});

// GET /api/v2/cases/:id/vuln-report/pdf — PDF download (analyst+ only, mirrors scan endpoint gating)
router.get("/:id/vuln-report/pdf", requireAuth, requireRole("analyst"), reportLimiter, async (req, res) => {
  try {
    const caseId = req.params.id;
    if (!isValidCaseId(caseId)) {
      return res.status(400).json({ error: "Invalid case ID" });
    }

    logger.info(`[vuln-report/pdf] Generating PDF for case ${caseId}`);
    const { pdf } = await generateVulnReport(parseInt(caseId, 10), "pdf", { caseStore, scanStore });

    const filename = `ipshield-vuln-assessment-case-${caseId}-${Date.now()}.pdf`;

    res.setHeader("Content-Type",        "application/pdf");
    res.setHeader("Content-Disposition", `attachment; filename="${filename}"`);
    res.setHeader("Content-Length",      pdf.length);
    res.send(pdf);
  } catch (err) {
    logger.error("[vuln-report/pdf]", err.message);
    if (err.message.includes("not found")) {
      return res.status(404).json({ error: "Case not found" });
    }
    res.status(500).json({ error: "PDF generation failed", detail: err.message });
  }
});

module.exports = router;