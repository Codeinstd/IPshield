
const express = require("express");
const router  = express.Router();
const { body, param, validationResult } = require("express-validator");
const { requireAuth, requireRole }      = require("../middleware/auth.js");
const { getBatchQueue }                 = require("../jobs/queues");
const { Queue }                         = require("bullmq");
const { getRedis }                      = require("../store/redis");

function validate(req, res, next) {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ error: "Validation failed", errors: errors.array() });
  next();
}

// ── POST /score/batch-async

router.post("/batch-async",
  requireAuth,
  requireRole("analyst"),
  [
    body("ips")
      .isArray({ min: 1, max: 500 })
      .withMessage("ips must be an array of 1–500 IP addresses"),
    body("ips.*")
      .trim()
      .custom(ip => {
        if (!/^(\d{1,3}\.){3}\d{1,3}$/.test(ip) && !/^[0-9a-fA-F:]{2,45}$/.test(ip))
          throw new Error(`Invalid IP: ${ip}`);
        return true;
      }),
    body("threshold")
      .optional()
      .isInt({ min: 0, max: 100 })
      .withMessage("threshold must be 0–100"),
    body("caseName")
      .optional()
      .trim()
      .isLength({ max: 200 }),
    body("addedBy")
      .optional()
      .trim()
      .isLength({ max: 100 }),
  ],
  validate,
  async (req, res) => {
    const queue = getBatchQueue();
    if (!queue) {
      return res.status(503).json({
        error:   "Queue unavailable",
        message: "Redis is not configured. Set REDIS_URL to enable async batch processing.",
      });
    }

    const { ips, threshold, caseName, addedBy } = req.body;

    try {
      const job = await queue.add("batch-score", {
        ips,
        threshold: threshold || null,
        caseName:  caseName  || null,
        addedBy:   addedBy   || req.apiKey?.name || "analyst",
      });

      res.status(202).json({
        jobId:   job.id,
        total:   ips.length,
        message: `Batch job queued — ${ips.length} IPs will be scored`,
        statusUrl: `/api/score/batch-async/${job.id}`,
      });
    } catch (err) {
      console.error("[batchAsync] Queue error:", err.message);
      res.status(500).json({ error: "Failed to enqueue batch job" });
    }
  }
);

// ── GET /score/batch-async/:jobId 

router.get("/batch-async/:jobId",
  requireAuth,
  requireRole("readonly"),
  [param("jobId").notEmpty()],
  validate,
  async (req, res) => {
    const redis = getRedis();
    if (!redis) {
      return res.status(503).json({ error: "Redis not available" });
    }

    try {
      // Re-attach to the queue to look up the job
      const queue = new Queue("batch-score", { connection: redis });
      const job   = await queue.getJob(req.params.jobId);

      if (!job) {
        return res.status(404).json({ error: "Job not found", jobId: req.params.jobId });
      }

      const state    = await job.getState();
      const progress = job.progress || 0;

      const response = {
        jobId:     job.id,
        status:    state,
        progress:  typeof progress === "number" ? `${progress}%` : progress,
        createdAt: new Date(job.timestamp).toISOString(),
      };

      if (state === "completed") {
        response.result      = job.returnvalue;
        response.completedAt = new Date(job.finishedOn).toISOString();
        response.durationMs  = job.finishedOn - job.timestamp;
      }

      if (state === "failed") {
        response.error       = job.failedReason;
        response.completedAt = new Date(job.finishedOn).toISOString();
      }

      await queue.close();
      res.json(response);
    } catch (err) {
      console.error("[batchAsync] Status error:", err.message);
      res.status(500).json({ error: "Failed to get job status" });
    }
  }
);

module.exports = router;