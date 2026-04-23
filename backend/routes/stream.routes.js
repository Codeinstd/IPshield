const express = require("express");
const router = express.Router();

const { getAbuseData } = require("../services/ipIntel.service");

router.get("/:ip", async (req, res) => {
  const ip = req.params.ip;

  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("Connection", "keep-alive");

  const send = (event, data) => {
    res.write(`event: ${event}\n`);
    res.write(`data: ${JSON.stringify(data)}\n\n`);
  };

  try {
    send("stage", { step: "Starting analysis..." });

    // Step 1: simulate geo lookup
    await new Promise(r => setTimeout(r, 500));
    send("stage", { step: "Checking geolocation..." });

    // Step 2: abuse intel
    const abuse = await getAbuseData(ip);
    send("stage", { step: "Analyzing threat intelligence..." });

    const score = abuse.abuseConfidenceScore;

    // Step 3: final result
    const result = {
      ip,
      score,
      riskLevel:
        score > 80 ? "CRITICAL" :
        score > 60 ? "HIGH" :
        score > 30 ? "MEDIUM" : "LOW",
      action:
        score > 80 ? "BLOCK" :
        score > 60 ? "CHALLENGE" :
        score > 30 ? "MONITOR" : "ALLOW",
      signals: [{
        category: "ABUSE",
        detail: `${abuse.totalReports} reports`,
        severity: score > 60 ? "high" : "medium"
      }],
      meta: { processingMs: Date.now() }
    };

    send("result", result);
    send("done", {});

    res.end();

  } catch (err) {
    send("error", { message: "Streaming failed" });
    res.end();
  }
});

module.exports = router;