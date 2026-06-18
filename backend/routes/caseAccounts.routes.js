
const express = require("express");
const router  = express.Router({ mergeParams: true });
const { body, param, validationResult } = require("express-validator");
const { requireAuth, requireRole }      = require("../middleware/auth.js");
const db = require("../store/db");
const ACCOUNT_TYPES = ["user","service","device","other"];

function validate(req, res, next) {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ error: "Validation failed", errors: errors.array() });
  next();
}

// POST /cases/:id/accounts 
router.post("/",
  requireAuth, requireRole("analyst"),
  [
    param("id").isInt({ min: 1 }),
    body("account_id").trim().notEmpty().isLength({ max: 200 })
      .withMessage("account_id is required"),
    body("account_type").optional().isIn(ACCOUNT_TYPES),
    body("note").optional().trim().isLength({ max: 500 }),
  ],
  validate,
  async (req, res) => {
    const caseId = parseInt(req.params.id);
    const { account_id, account_type = "user", note } = req.body;

    try {
      // Check case exists
      const caseCheck = await db.query(
        `SELECT id FROM cases WHERE id = $1`, [caseId]
      );
      if (!caseCheck.rows.length) {
        return res.status(404).json({ error: "Case not found" });
      }

      // Duplicate check
      const dup = await db.query(
        `SELECT id FROM case_accounts WHERE case_id = $1 AND account_id = $2`,
        [caseId, account_id]
      );
      if (dup.rows.length) {
        return res.status(409).json({ error: "Account already attached to this case" });
      }

      const result = await db.query(
        `INSERT INTO case_accounts (case_id, account_id, account_type, note)
         VALUES ($1, $2, $3, $4)
         RETURNING *`,
        [caseId, account_id, account_type, note || null]
      );

      // Touch case updated_at
      await db.query(
        `UPDATE cases SET updated_at = NOW() WHERE id = $1`, [caseId]
      );

      res.status(201).json(result.rows[0]);
    } catch (err) {
  next(err);
}
  }
);

// GET /cases/:id/accounts 

router.get("/",
  requireAuth, requireRole("readonly"),
  [param("id").isInt({ min: 1 })],
  validate,
  async (req, res) => {
    const caseId = parseInt(req.params.id);
    try {
      const result = await db.query(
        `SELECT * FROM case_accounts
         WHERE case_id = $1
         ORDER BY added_at DESC`,
        [caseId]
      );
      res.json({ case_id: caseId, total: result.rows.length, accounts: result.rows });
    } catch (err) {
  next(err);
}
  }
);

// DELETE /cases/:id/accounts/:accId 

router.delete("/:accId",
  requireAuth, requireRole("analyst"),
  [
    param("id").isInt({ min: 1 }),
    param("accId").isInt({ min: 1 }),
  ],
  validate,
  async (req, res) => {
    try {
      const result = await db.query(
        `DELETE FROM case_accounts
         WHERE id = $1 AND case_id = $2
         RETURNING id`,
        [parseInt(req.params.accId), parseInt(req.params.id)]
      );
      if (!result.rows.length) {
        return res.status(404).json({ error: "Account not found on this case" });
      }
      await db.query(
        `UPDATE cases SET updated_at = NOW() WHERE id = $1`,
        [parseInt(req.params.id)]
      );
      res.json({ message: "Account removed from case" });
    } catch (err) {
  next(err);
}
  }
);

module.exports = router;