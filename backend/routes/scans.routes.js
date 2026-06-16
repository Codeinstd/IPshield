const express = require("express");
const router = express.Router();
const scanController = require("../controllers/scanController");
const { getScanQueue } = require("../jobs/queues");


// Direct scan triggers
router.post("/nmap", scanController.runNmap);
router.post("/nuclei", scanController.runNuclei);

// Unified scan (UI uses this)
router.post("/start", async (req, res) => {
  try {
    const { target, type = "full" } = req.body;

    const check = await validateTarget(target);

    if (!check.ok) {
      return res.status(400).json({
        success: false,
        error: check.error
      });
    }

    const queue = getScanQueue();

    if (!queue) {
      return res.status(500).json({
        success: false,
        error: "Scan queue not initialized"
      });
    }

    const job = await queue.add("security-scan", {
      target,
      type,
      ts: Date.now()
    });

    res.json({
      success: true,
      jobId: job.id
    });

  } catch (err) {
    console.error("SCAN START ERROR:", err);
    res.status(500).json({
      success: false,
      error: err.message
    });
  }
});

// Poll scan progress
router.get("/:id", async (req, res) => {
  try {
    const queue = getScanQueue();
    const job = await queue.getJob(req.params.id);

    if (!job) {
      return res.status(404).json({ error: "Scan not found" });
    }

    const state = await job.getState();

    res.json({
      id: job.id,
      state,
      progress: job.progress || 0,
      result: job.returnvalue || null
    });
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch scan" });
  }
});

module.exports = router;