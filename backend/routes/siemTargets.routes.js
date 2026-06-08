
const express = require("express");
const router  = express.Router();
const { body, param, validationResult } = require("express-validator");
const { requireAuth, requireRole }      = require("../middleware/auth.js");
const {
  listTargets, createTarget, updateTarget, deleteTarget, testTarget,
} = require("../services/siemTargets.service");

const SIEM_TYPES = ["splunk","elastic","sentinel","qradar","generic"];
const RISK_LEVELS = ["LOW","MEDIUM","HIGH","CRITICAL"];

function validate(req, res, next) {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ error: "Validation failed", errors: errors.array() });
  next();
}

// GET /siem/targets 

router.get("/targets", requireAuth, requireRole("readonly"), async (req, res) => {
  try {
    const targets = await listTargets();
    res.json({ total: targets.length, targets });
  } catch (err) {
  next(err);
}
});

// POST /siem/targets 

router.post("/targets",
  requireAuth, requireRole("admin"),
  [
    body("name").trim().notEmpty().isLength({ max: 100 }),
    body("type").isIn(SIEM_TYPES),
    body("url").isURL(),
    body("token").optional().trim().isLength({ max: 500 }),
    body("enabled").optional().isBoolean(),
    body("minScore").optional().isInt({ min: 0, max: 100 }),
    body("minRisk").optional().isIn(RISK_LEVELS),
    body("verifySsl").optional().isBoolean(),
  ],
  validate,
  async (req, res) => {
    try {
      const target = await createTarget(req.body);
      res.status(201).json(target);
    } catch (err) {
  next(err);
}
  }
);

// PUT /siem/targets/:id 

router.put("/targets/:id",
  requireAuth, requireRole("admin"),
  [
    param("id").isInt({ min: 1 }),
    body("name").optional().trim().isLength({ max: 100 }),
    body("type").optional().isIn(SIEM_TYPES),
    body("url").optional().isURL(),
    body("token").optional().trim().isLength({ max: 500 }),
    body("enabled").optional().isBoolean(),
    body("min_score").optional().isInt({ min: 0, max: 100 }),
    body("min_risk").optional().isIn(RISK_LEVELS),
    body("verify_ssl").optional().isBoolean(),
  ],
  validate,
  async (req, res) => {
    try {
      const target = await updateTarget(parseInt(req.params.id), req.body);
      if (!target) return res.status(404).json({ error: "Target not found" });
      res.json(target);
    } catch (err) {
  next(err);
}
  }
);

// DELETE /siem/targets/:id 

router.delete("/targets/:id",
  requireAuth, requireRole("admin"),
  [param("id").isInt({ min: 1 })],
  validate,
  async (req, res) => {
    try {
      const ok = await deleteTarget(parseInt(req.params.id));
      if (!ok) return res.status(404).json({ error: "Target not found" });
      res.json({ message: "SIEM target removed" });
    } catch (err) {
  next(err);
}
  }
);

// POST /siem/targets/:id/test 

router.post("/targets/:id/test",
  requireAuth, requireRole("analyst"),
  [param("id").isInt({ min: 1 })],
  validate,
  async (req, res) => {
    try {
      const result = await testTarget(parseInt(req.params.id));
      res.json({
        success: result.success,
        message: result.success ? "✓ Test event delivered" : `✗ Failed: ${result.reason}`,
        ...result,
      });
    } catch (err) {
  next(err);
}
  }
);

module.exports = router;