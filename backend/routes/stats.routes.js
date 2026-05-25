const express = require("express");
const router = express.Router();
const { getStats } = require("../controllers/stats.controller");
const { requireAuth, requireRole } = require("../middleware/auth.js");

router.get("/", requireAuth, requireRole('readonly'), getStats);

module.exports = router;