// backend/routes/proxy.routes.js
const express = require("express");
const router  = express.Router();
const { scoreIP } = require("../controllers/score.controller");

// Public-facing — no auth, but rate limited
router.get("/:ip", scoreIP);
module.exports = router;