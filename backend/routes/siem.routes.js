const express = require("express");
const router  = express.Router();
const { body, param, validationResult } = require("express-validator");
const { sendToSIEM, testSIEM, getSIEMStatus, buildGenericPayload } = require("../services/siem.service");
const logger = require("../utils/logger");

const FORMATS = [
  { id:"splunk",   label:"Splunk HEC",            description:"Splunk HTTP Event Collector format. Set SIEM_TOKEN to your HEC token." },
  { id:"elastic",  label:"Elastic / OpenSearch",   description:"ECS-compatible format for Elasticsearch. Set SIEM_TOKEN to your API key." },
  { id:"sentinel", label:"Microsoft Sentinel",     description:"Azure Log Analytics custom log format. Set SIEM_TOKEN to your SharedKey." },
  { id:"qradar",   label:"IBM QRadar",             description:"CEF (Common Event Format) syslog payload. Set SIEM_TOKEN to your SEC token." },
  { id:"generic",  label:"Generic JSON Webhook",   description:"Universal JSON format for any webhook receiver, Zapier, Make, n8n, etc." }
];

// GET /api/siem/status
router.get("/status", (req, res) => {
  res.json({ siem: getSIEMStatus() });
});

// GET /api/siem/formats
router.get("/formats", (req, res) => {
  res.json({ formats: FORMATS });
});

// GET /api/siem/sample/:format
router.get("/sample/:format",
  [param("format").isIn(FORMATS.map(f => f.id))],
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ error: "Unknown format", supported: FORMATS.map(f => f.id) });

    const mockResult = {
      ip:"185.220.101.1", score:95, baseScore:85, scoreBoost:10,
      riskLevel:"CRITICAL", action:"BLOCK",
      geo:{ country:"Germany", city:"Frankfurt", region:"Hesse", timezone:"Europe/Berlin", lat:50.1109, lon:8.6821 },
      network:{ isp:"Example ISP GmbH", asn:"AS60729", type:"hosting" },
      intelligence:{ isProxy:false, isTor:true, isDatacenter:true, velocity:"HIGH", openPorts:[80,443,9001], vulns:[], shodanTags:["tor","scanner"] },
      threatFeeds:{ feodo:true, spamhaus:false, emergingThreats:true, otx:{ pulseCount:3, pulseNames:["Tor Exit Nodes"], tags:["tor"] } },
      whois:{ orgName:"Example Org", orgId:"EX-1", country:"DE", abuseEmail:"abuse@example.com", agedays:2847 },
      signals:[{ category:"ABUSE", detail:"Score 95/100", severity:"critical" }],
      meta:{ processingMs:842, cached:false, scoredAt:new Date() }
    };

    // Build sample using the service's internal builders
    const { buildGenericPayload } = require("../services/siem.service");
    // For demo, always return generic — format-specific builders are internal
    const sample = buildGenericPayload(mockResult);
    res.json({ format: req.params.format, sample });
  }
);

// POST /api/siem/test
router.post("/test",
  [
    body("url").optional().isURL(),
    body("type").optional().isIn(FORMATS.map(f => f.id)),
    body("token").optional().isString()
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ error: "Validation failed", errors: errors.array() });

    logger.info("SIEM test webhook triggered");
    const result = await testSIEM(req.body);
    res.json({
      success: result.sent,
      status:  result.status,
      reason:  result.reason || null,
      message: result.sent
        ? "✓ Test event delivered successfully"
        : `✗ Delivery failed: ${result.reason}`
    });
  }
);

module.exports = router;