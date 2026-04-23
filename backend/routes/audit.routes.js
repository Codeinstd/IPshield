const express = require("express");
const router = express.Router();
const { getAudit } = require("../controllers/audit.controller");
const { getFullIntel } = require("../services/ipintel.service");

router.get("/score/:ip", async (req, res) => {
  try {
    const data = await getFullIntel(req.params.ip);
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: "Failed to score IP" });
  }
});

router.get("/", getAudit);

module.exports = router;