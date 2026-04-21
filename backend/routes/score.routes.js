const express = require("express");
const router = express.Router();

const { getAbuseData } = require("../services/ipIntel.service");
const retry = require("../utils/retry");

function setIP(ip) {
  if (!ip || typeof ip !== "string") {
    console.warn("Invalid IP passed to setIP:", ip);
    return;
  }

  const input = document.getElementById('ipInput');
  if (!input) return;

  input.value = ip;
  scoreIP();
}


router.get("/:ip", async (req, res) => {
  try {
    const ip = req.params.ip;

    const abuse = await retry(() => getAbuseData(ip), 3, 500);

    const score = abuse.abuseConfidenceScore;

    res.json({
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
      signals: [
        {
          category: "ABUSE",
          detail: `${abuse.totalReports} reports`,
          severity: score > 60 ? "high" : "medium"
        }
      ],
      geo: {},
      network: { type: "unknown", isDatacenter: false },
      behavior: {
        requestsLast5Min: 1,
        velocityLabel: "LOW",
        firstSeen: Date.now()
      },
      meta: {
        processingMs: 120,
        scoredAt: Date.now()
      }
    });

  } catch (err) {
    console.error("IP scoring failed after retries:", err);

    res.status(503).json({
      error: "Service temporarily unavailable",
      retryable: true
    });
  }
});

//


module.exports = router;