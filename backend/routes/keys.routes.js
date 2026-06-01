
const express = require("express");
const router  = express.Router();
const { body, param, query, validationResult } = require("express-validator");
const { requireAuth, requireRole }             = require("../middleware/auth.js");
const km = require("../services/keyManager.service");
const { sendEmailAlert } = require("../services/alerts.service");
const db = require("../store/db");

const ROLES = ["readonly","analyst","admin"];

function validate(req, res, next) {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ error: "Validation failed", errors: errors.array() });
  next();
}

// ── GET /api/keys/stats 

router.get("/stats", requireAuth, requireRole("admin"), async (req, res) => {
  try {
    const stats = await km.getKeyStats();
    res.json(stats);
  } catch (err) {
    res.status(500).json({ error: "Failed to load stats" });
  }
});

// ── GET /api/keys

router.get("/",
  requireAuth, requireRole("admin"),
  [
    query("status").optional().isIn(["pending","active","revoked","suspended"]),
    query("role").optional().isIn(ROLES),
    query("limit").optional().isInt({ min: 1, max: 200 }),
    query("offset").optional().isInt({ min: 0 }),
  ],
  validate,
  async (req, res) => {
    try {
      const result = await km.listKeys({
        status: req.query.status,
        role:   req.query.role,
        limit:  parseInt(req.query.limit  || "100"),
        offset: parseInt(req.query.offset || "0"),
      });
      res.json(result);
    } catch (err) {
      res.status(500).json({ error: "Failed to list keys" });
    }
  }
);

// ── POST /api/keys/invite 

router.post("/invite",
  requireAuth, requireRole("admin"),
  [
    body("name").trim().notEmpty().isLength({ max: 100 }),
    body("email").optional().isEmail().normalizeEmail(),
    body("role").optional().isIn(ROLES),
    body("dailyLimit").optional().isInt({ min: 1, max: 1000000 }),
    body("notes").optional().trim().isLength({ max: 500 }),
  ],
  validate,
  async (req, res) => {
     console.log('[invite] body:', req.body);
    try {
      const invite = await km.createInvite({
        ...req.body,
        invitedBy: req.apiKey?.name || "admin",
      });

      // Send invite email if email provided and SMTP configured
     if (req.body.email && process.env.SMTP_HOST) {
  const nodemailer = require("nodemailer");
  const transporter = nodemailer.createTransport({
    host:   process.env.SMTP_HOST,
    port:   parseInt(process.env.SMTP_PORT || "587"),
    secure: process.env.SMTP_PORT === "465",
    auth:   { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
  });

  transporter.sendMail({
    from:    process.env.ALERT_FROM || process.env.SMTP_USER,
    to:      req.body.email,   // ← recipient, not ALERT_TO
    subject: "Your IPShield API Access",
    html: `
      <div style="background:#0d1117;padding:32px;font-family:monospace;max-width:560px;margin:0 auto;">
        <h2 style="color:#c9d8e8;">IP<span style="color:#00d9ff;">Shield</span> — You're invited</h2>
        <p style="color:#8fa8bc;">Hi ${invite.name},<br><br>
        You've been granted access to the IPShield API.<br>
        Click below to activate your key:</p>
        <div style="margin:24px 0;text-align:center;">
          <a href="${invite.activateUrl}"
            style="background:#00d9ff;color:#000;padding:12px 32px;border-radius:6px;
                   text-decoration:none;font-weight:700;display:inline-block;">
            Activate API Key →
          </a>
        </div>
        <p style="color:#4a6278;font-size:11px;">
          Role: ${invite.role} · Daily limit: ${invite.daily_limit} requests<br>
          This link expires in 7 days. Do not share it.
        </p>
      </div>`,
  }).catch(err => console.error("[invite] Email error:", err.message));
}

      res.status(201).json({
        id:           invite.id,
        name:         invite.name,
        email:        invite.email,
        role:         invite.role,
        status:       invite.status,
        daily_limit:  invite.daily_limit,
        activateUrl:  invite.activateUrl,
        invite_token: invite.invite_token,
        message:      "Invite created. Share the activateUrl with the recipient.",
      });
    } catch (err) {
      console.error("[keys] Create invite error:", err.message);
      res.status(500).json({ error: "Failed to create invite" });
    }
  }
);

// ── GET /api/keys/activate/:token — check token validity 

router.get("/activate/:token",
  [ param("token").trim().notEmpty().isLength({ min: 40, max: 60 })],
  validate,
  async (req, res) => {
    console.log("[activate] HIT — token:", req.params.token);
    try {
      const res2 = await require("../store/db").query(
        `SELECT name, email, role, daily_limit, invited_at
         FROM api_keys WHERE invite_token = $1 AND status = 'pending'`,
        [req.params.token]
      );
      if (!res2.rows.length) {
        return res.status(404).json({ valid: false, error: "Invalid or expired invite token" });
      }
      res.json({ valid: true, invite: res2.rows[0] });
    } catch (err) {
      res.status(500).json({ error: "Token check failed" });
    }
  }
);

// ── POST /api/keys/activate/:token — activate 

router.post("/activate/:token",
  [ param("token").trim().notEmpty().isLength({ min: 40, max: 60 })],
  validate,
  async (req, res) => {
    try {
      const activated = await km.activateInvite(req.params.token);
      if (!activated) {
        return res.status(404).json({ error: "Invalid or already-used invite token" });
      }
      // Fetch the full key to return it (only time it's shown)
      const full = await require("../store/db").query(
        `SELECT key, name, email, role, daily_limit FROM api_keys WHERE id = $1`,
        [activated.id]
      );

      res.json({
        message:     "API key activated successfully. Save your key — it will not be shown again.",
        key:         full.rows[0].key,
        name:        activated.name,
        role:        activated.role,
        daily_limit: activated.daily_limit,
      });
    } catch (err) {
      res.status(500).json({ error: "Activation failed" });
    }
  }
);

// ── GET /api/keys/:id

router.get("/:id",
  requireAuth, requireRole("admin"),
  [param("id").isInt({ min: 1 })],
  validate,
  async (req, res) => {
    try {
      const key = await km.getKey(parseInt(req.params.id));
      if (!key) return res.status(404).json({ error: "Key not found" });
      // Mask the actual key
      res.json({ ...key, key: key.key.slice(0, 8) + "••••••••••••••••••••••••" });
    } catch (err) {
      res.status(500).json({ error: "Failed to get key" });
    }
  }
);

// ── PUT /api/keys/:id 

router.put("/:id",
  requireAuth, requireRole("admin"),
  [
    param("id").isInt({ min: 1 }),
    body("name").optional().trim().isLength({ max: 100 }),
    body("email").optional().isEmail(),
    body("role").optional().isIn(ROLES),
    body("dailyLimit").optional().isInt({ min: 1 }),
    body("notes").optional().trim().isLength({ max: 500 }),
  ],
  validate,
  async (req, res) => {
    try {
      const updated = await km.updateKey(parseInt(req.params.id), req.body);
      if (!updated) return res.status(404).json({ error: "Key not found" });
      res.json(updated);
    } catch (err) {
      res.status(500).json({ error: "Failed to update key" });
    }
  }
);

// ── POST /api/keys/:id/revoke 

router.post("/:id/revoke",
  requireAuth, requireRole("admin"),
  [
    param("id").isInt({ min: 1 }),
    body("reason").optional().trim().isLength({ max: 200 }),
  ],
  validate,
  async (req, res) => {
    try {
      const ok = await km.revokeKey(parseInt(req.params.id), req.body.reason);
      if (!ok) return res.status(404).json({ error: "Key not found or already revoked" });
      res.json({ message: "Key revoked" });
    } catch (err) {
      res.status(500).json({ error: "Failed to revoke key" });
    }
  }
);

// ── POST /api/keys/:id/suspend 

router.post("/:id/suspend",
  requireAuth, requireRole("admin"),
  [param("id").isInt({ min: 1 })],
  validate,
  async (req, res) => {
    try {
      await km.suspendKey(parseInt(req.params.id));
      res.json({ message: "Key suspended" });
    } catch (err) {
      res.status(500).json({ error: "Failed to suspend key" });
    }
  }
);

// ── DELETE /api/keys/:id

router.delete("/:id",
  requireAuth, requireRole("admin"),
  [param("id").isInt({ min: 1 })],
  validate,
  async (req, res) => {
    try {
      const result = await db.query(
        `DELETE FROM api_keys WHERE id = $1 RETURNING id, name`,
        [parseInt(req.params.id)]
      );
      if (!result.rows.length) {
        return res.status(404).json({ error: "Key not found" });
      }
      res.json({ message: `Key "${result.rows[0].name}" permanently deleted` });
    } catch (err) {
      res.status(500).json({ error: "Failed to delete key" });
    }
  }
);

// ── POST /api/keys/:id/reinstate

router.post("/:id/reinstate",
  requireAuth, requireRole("admin"),
  [param("id").isInt({ min: 1 })],
  validate,
  async (req, res) => {
    try {
      await km.reinstateKey(parseInt(req.params.id));
      res.json({ message: "Key reinstated" });
    } catch (err) {
      res.status(500).json({ error: "Failed to reinstate key" });
    }
  }
);

// ── POST /api/keys/:id/rotate 

router.post("/:id/rotate",
  requireAuth, requireRole("admin"),
  [param("id").isInt({ min: 1 })],
  validate,
  async (req, res) => {
    try {
      const result = await km.rotateKey(parseInt(req.params.id));
      if (!result) return res.status(404).json({ error: "Key not found or not active" });
      res.json({
        message: "Key rotated. Save the new key — it will not be shown again.",
        newKey:  result.newKey,
        name:    result.name,
      });
    } catch (err) {
      res.status(500).json({ error: "Failed to rotate key" });
    }
  }
);

// ── GET /api/keys/:id/usage 

router.get("/:id/usage",
  requireAuth, requireRole("admin"),
  [
    param("id").isInt({ min: 1 }),
    query("days").optional().isInt({ min: 1, max: 90 }),
  ],
  validate,
  async (req, res) => {
    try {
      const usage = await km.getKeyUsage(
        parseInt(req.params.id),
        parseInt(req.query.days || "30")
      );
      res.json({ key_id: parseInt(req.params.id), days: parseInt(req.query.days || "30"), usage });
    } catch (err) {
      res.status(500).json({ error: "Failed to load usage" });
    }
  }
);

module.exports = router;