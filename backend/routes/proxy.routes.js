// backend/routes/proxy.routes.js
const express = require("express");
const router  = express.Router();
const { scoreIP } = require("../controllers/score.controller");
const { requireAuth, requireRole } = require("../middleware/auth.js");

// Public-facing — no auth, but rate limited
router.get("/:ip", requireAuth, requireRole('readonly'), scoreIP);
module.exports = router;