const express = require("express");
const { v4: uuidv4 } = require("uuid");
const router = express.Router();

const scan = require("../store/scan.store.js");
const { enqueueScan, getScanQueue } = require("../jobs/scanWorker");
const logger = require("../utils/logger");
const { requireAuth, requireRole } = require("../middleware/auth.js");

// Helpers
const IPv4_RE = /^(\d{1,3}\.){3}\d{1,3}$/;
const IPv6_RE = /^[0-9a-fA-F:]+$/;

function isValidIP(ip) {
  return IPv4_RE.test(ip) || IPv6_RE.test(ip);
}

function isPrivateIP(ip) {
  const PRIVATE = [
    /^10\./,
    /^172\.(1[6-9]|2\d|3[01])\./,
    /^192\.168\./,
    /^127\./,
    /^::1$/,
    /^fc|fd/i,
    /^169\.254\./,
  ];
  return PRIVATE.some((re) => re.test(ip));
}

// POST /api/v2/scan/:ip
router.post("/:ip", requireAuth, requireRole("admin"), async (req, res) => {
  const { ip } = req.params;
  const { consent } = req.body;

  if (!isValidIP(ip)) {
    return res.status(400).json({ error: "Invalid IP address" });
  }

  if (isPrivateIP(ip)) {
    return res.status(400).json({
      error: "Scanning private/reserved IP ranges is not permitted",
    });
  }

  if (!consent) {
    return res.status(400).json({
      error: "Consent required",
    });
  }

  const queue = getScanQueue();

  const waiting = await queue.getWaiting();
  const active = await queue.getActive();

  const allJobs = [...waiting, ...active];

  const inFlight = allJobs.find((job) => job.data.ip === ip);

  if (inFlight) {
    return res.status(409).json({
      error: "A scan is already in progress for this IP",
      jobId: inFlight.data.jobId,
      status: await inFlight.getState(),
    });
  }

  // Create job
  const jobId = uuidv4();
  const requestedBy = req.user?.id ?? req.user?.name ?? "unknown";

  try {
    await scan.createJob({ jobId, ip, requestedBy, consent: true });
    await enqueueScan({ jobId, ip, requestedBy });

    logger.info(`[scan] queued ${jobId} for ${ip}`);

    return res.status(202).json({
      jobId,
      ip,
      status: "queued",
      pollUrl: `/api/v2/scan/job/${jobId}`,
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({
      error: err.message,
      stack: err.stack,
    });
  }
});

// GET job status
router.get("/job/:jobId", async (req, res) => {
  const job = await scan.getJob(req.params.jobId);

  if (!job) return res.status(404).json({ error: "Job not found" });

  const results = (job.results ?? []).map((r) => ({
    scanner: r.scanner,
    severity: r.severity,
    summary: r.summary,
  }));

  return res.json({
    jobId: job.job_id,
    ip: job.ip,
    status: job.status,
    results,
  });
});

// History
router.get("/history/:ip", async (req, res) => {
  const scans = await scan.getRecentScans(req.params.ip, 5);

  return res.json({
    ip: req.params.ip,
    scans,
  });
});

// Raw scan
router.get(
  "/job/:jobId/raw/:scanner",
  requireAuth,
  requireRole("admin"),
  async (req, res) => {
    const { scanner } = req.params;

    if (!["nmap", "nuclei"].includes(scanner)) {
      return res.status(400).json({ error: "scanner must be nmap or nuclei" });
    }

    const job = await scan.getJob(req.params.jobId);

    if (!job) return res.status(404).json({ error: "Job not found" });

    const result = (job.results ?? []).find((r) => r.scanner === scanner);

    if (!result) {
      return res.status(404).json({ error: `No ${scanner} result yet` });
    }

    return res.json({
      jobId: job.job_id,
      scanner,
      raw: result.raw,
      severity: result.severity,
    });
  }
);

module.exports = router;