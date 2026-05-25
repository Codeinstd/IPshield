
const express  = require("express");
const router   = express.Router();
const { scoreIP, scoreBatch }             = require("../controllers/score.controller");
const { validateIPParam, validateBatchBody } = require("../middleware/validateIP.middleware");
const { requireAuth, requireRole } = require("../middleware/auth.js");

router.get("/:ip",   requireAuth, requireRole('readonly'), validateIPParam,   scoreIP);
router.post("/batch", requireAuth, requireRole('readonly'), validateBatchBody, scoreBatch);

module.exports = router;