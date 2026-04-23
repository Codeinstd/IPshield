const express = require("express");
const router = express.Router();
const { getFullIntel } = require("../services/ipintel.service"); // one import, consistent casing

router.get("/:ip", async (req, res) => {
  try {
    const data = await getFullIntel(req.params.ip);
    res.json(data);
  } catch (err) {
    console.error("IP scoring failed:", err);
    res.status(503).json({
      error: "Service temporarily unavailable",
      retryable: true
    });
  }
});

module.exports = router;