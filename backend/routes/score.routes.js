const express  = require("express");
const router   = express.Router();

const { scoreIP, scoreBatch }              = require("../controllers/score.controller");
const { scoreBatchAndBlock }              = require("../controllers/scorebatchandblock.controller");
const { validateIPParam, validateBatchBody } = require("../middleware/validateIP.middleware");
const { requireAuth, requireRole }         = require("../middleware/auth.js");
const { validateBatchAndBlockBody }        = require("../middleware/validateBatchAndBlockBody.middleware");

// Existing routes (unchanged)
router.get("/:ip",    requireAuth, requireRole("readonly"), validateIPParam,    scoreIP);
router.post("/batch", requireAuth, requireRole("readonly"), validateBatchBody,  scoreBatch);

// Phase 2 — batch-and-block
// Requires `analyst` role: this endpoint writes to the blacklist.
// Route must be defined BEFORE "/:ip" to avoid Express matching "batch-and-block" as an IP param.
router.post(
  "/batch-and-block",
  validateBatchAndBlockBody,
  scoreBatchAndBlock
);

module.exports = router;