
const express = require("express");
const router  = express.Router();
const { body, param, validationResult } = require("express-validator");
const { requireAuth, requireRole }      = require("../middleware/auth.js");
const db = require("../store/db");

function validate(req, res, next) {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ error: "Validation failed", errors: errors.array() });
  next();
}

// POST /blacklist/cidr 

router.post("/",
  requireAuth, requireRole("analyst"),
  [
    body("cidr")
      .trim().notEmpty()
      .matches(/^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/)
      .withMessage("Must be a valid CIDR e.g. 185.220.101.0/24"),
    body("asn").optional().trim().isLength({ max: 20 }),
    body("severity").optional().isIn(["CRITICAL","HIGH","MEDIUM","LOW"]),
    body("reason").optional().trim().isLength({ max: 500 }),
    body("tags").optional().isArray(),
    body("expires_at").optional().isISO8601(),
  ],
  validate,
  async (req, res) => {
    const { cidr, asn, severity = "HIGH", reason, tags = [], expires_at } = req.body;
    try {
      const dupCheck = await db.query(
        `SELECT id FROM cidr_blocks WHERE cidr = $1::cidr`,
        [cidr]
      );
      if (dupCheck.rows.length) {
        return res.status(409).json({ error: "CIDR already blocked", id: dupCheck.rows[0].id });
      }

      const result = await db.query(
        `INSERT INTO cidr_blocks (cidr, asn, severity, reason, added_by, expires_at, tags)
         VALUES ($1::cidr, $2, $3, $4, $5, $6, $7)
         RETURNING *`,
        [cidr, asn || null, severity, reason || null,
         req.auth?.name || "analyst", expires_at || null, tags]
      );

      res.status(201).json(result.rows[0]);
    } catch (err) {
      console.error("[cidr] Insert error:", err.message);
      res.status(500).json({ error: "Failed to add CIDR block" });
    }
  }
);

// GET /blacklist/cidr 

router.get("/", requireAuth, requireRole("readonly"), async (req, res) => {
  try {
    const result = await db.query(
      `SELECT * FROM cidr_blocks
       WHERE expires_at IS NULL OR expires_at > NOW()
       ORDER BY added_at DESC`
    );
    res.json({ total: result.rows.length, blocks: result.rows });
  } catch (err) {
    res.status(500).json({ error: "Failed to list CIDR blocks" });
  }
});

// GET /blacklist/cidr/check/:ip

router.get("/check/:ip",
  requireAuth, requireRole("readonly"),
  [param("ip").trim().notEmpty()],
  validate,
  async (req, res) => {
    try {

      // Postgres inet >> operator: does the CIDR contain this IP?
      const result = await db.query(
        `SELECT id, cidr::text AS cidr, severity, reason, asn, added_at
         FROM cidr_blocks
         WHERE cidr >> $1::inet
           AND (expires_at IS NULL OR expires_at > NOW())
         LIMIT 1`,
        [req.params.ip]
      );

      if (result.rows.length) {
        res.json({ blocked: true,  block: result.rows[0] });
      } else {
        res.json({ blocked: false, block: null });
      }
    } catch (err) {
      console.error("[cidr] Check error:", err.message);
      res.status(500).json({ error: "CIDR check failed" });
    }
  }
);

// DELETE /blacklist/cidr/:id 

router.delete("/:id",
  requireAuth, requireRole("analyst"),
  [param("id").isInt({ min: 1 })],
  validate,
  async (req, res) => {
    try {
      const result = await db.query(
        `DELETE FROM cidr_blocks WHERE id = $1 RETURNING id`,
        [parseInt(req.params.id)]
      );
      if (!result.rows.length) return res.status(404).json({ error: "CIDR block not found" });
      res.json({ message: "CIDR block removed", id: parseInt(req.params.id) });
    } catch (err) {
      res.status(500).json({ error: "Failed to remove CIDR block" });
    }
  }
);

module.exports = router;