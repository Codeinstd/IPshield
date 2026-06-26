const express  = require("express");
const router   = express.Router();
const crypto = require("crypto");
const { hashKey } = require("../utils/keyHash");
const { body, param, query, validationResult } = require("express-validator");
const { requireAuth, requireRole } = require("../middleware/auth.js");
const km = require("../services/keyManager.service");
const { sendEmail, sendAlertEmail, sendInviteEmail } = require("../services/email.service");
const db = require("../store/db");

const ROLES = ["readonly", "analyst", "admin"];

function validate(req, res, next) {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ error: "Validation failed", errors: errors.array() });
  }
  next();
}

// GET /api/keys/stats 

router.get("/stats",
  requireAuth, requireRole("admin"),
  async (req, res) => {
    try {
      const stats = await km.getKeyStats();
      res.json(stats);
    } catch (err) {
      console.error("[keys/stats]", err.message);
      res.status(500).json({ error: err.message });
    }
  }
);

// POST /api/keys/access-request 
router.post("/access-request", async (req, res) => {
  try {
    const { name, email, company } = req.body;

    if (!name || !email || !company) {
      return res.status(400).json({ error: "Missing fields" });
    }

    const ts = new Date().toUTCString();

    await sendEmail({
      to:      process.env.ALERT_TO,
      subject: `[IPShield] New Access Request — ${name}`,
      html: `
        <div style="background:#0d1117;padding:32px;font-family:monospace;max-width:520px;margin:0 auto;">
          <h2 style="color:#c9d8e8;margin-bottom:20px;">
            IP<span style="color:#00d9ff;">Shield</span> — New Access Request
          </h2>
          <table style="width:100%;border-collapse:collapse;font-size:13px;">
            ${[["Name", name], ["Email", email], ["Organisation", company], ["Submitted", ts]]
              .map(([k, v]) => `
                <tr>
                  <td style="padding:8px 12px;color:#4a6278;border-bottom:1px solid #1e2d3d;width:120px;">${k}</td>
                  <td style="padding:8px 12px;color:#c9d8e8;border-bottom:1px solid #1e2d3d;">${v}</td>
                </tr>`)
              .join("")}
          </table>
        </div>`,
    });

    return res.json({ ok: true });

  } catch (err) {
    console.error("[access-request]", err.message);
    return res.status(500).json({ error: "Failed to send access request email" });
  }
});

// GET /api/keys 

router.get("/",
  requireAuth, requireRole("admin"),
  [
    query("status").optional().isIn(["pending", "active", "revoked", "suspended"]),
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
      console.error("[keys/list]", err.message);
      res.status(500).json({ error: err.message });
    }
  }
);

// POST /api/keys/invite 
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
    try {
      const invite = await km.createInvite({
        name:       req.body.name,
        email:      req.body.email,
        role:       req.body.role || "analyst",
        dailyLimit: req.body.dailyLimit,
        notes:      req.body.notes,
        invitedBy:  req.auth?.name || req.auth?.email || "admin",
      });

      if (invite.email) {
        sendInviteEmail(invite).catch(err => {
          console.error("[invite/email]", err.message);
        });
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
        expiresAt:    invite.invite_expires_at,
        message:      "Invite created. Share the activateUrl with the recipient.",
      });

    } catch (err) {
      console.error("[keys/invite]", err.message);
      res.status(500).json({ error: err.message });
    }
  }
);

// GET /api/keys/me 
router.get("/me", requireAuth, async (req, res) => {
  if (!req.auth) return res.status(401).json({ error: "Unauthorized" });
  res.json(req.auth);
});

// GET /api/keys/activate/:token 
// Validates token and returns invite metadata for the activation form
router.get("/activate/:token",
  [param("token").trim().notEmpty().isLength({ min: 20, max: 120 })],
  validate,
  async (req, res) => {
    try {
      const result = await db.query(
        `SELECT name, email, role, daily_limit, invited_at, invite_expires_at
         FROM api_keys
         WHERE invite_token = $1
           AND status = 'pending'
           AND invite_expires_at > NOW()`,
        [req.params.token]
      );

      if (!result.rows.length) {
        // Check if it exists but is expired — give a clearer error
        const expired = await db.query(
          `SELECT id FROM api_keys
           WHERE invite_token = $1
             AND status = 'pending'
             AND invite_expires_at <= NOW()`,
          [req.params.token]
        );

        if (expired.rows.length) {
          return res.status(410).json({
            valid: false,
            error: "This invite link has expired — ask an admin to send a new one",
          });
        }

        return res.status(404).json({
          valid: false,
          error: "Invalid or already-used invite link",
        });
      }

      // Don't expose daily_limit — not needed on the activation form
      const { name, email, role, invited_at } = result.rows[0];
      res.json({ valid: true, invite: { name, email, role, invited_at } });

    } catch (err) {
      console.error("[activate/get]", err.message);
      res.status(500).json({ error: err.message });
    }
  }
);

// POST /api/keys/activate/:token 
router.post("/activate/:token",
  [param("token").trim().notEmpty().isLength({ min: 20, max: 120 })],
  validate,
  async (req, res) => {
    try {
      const { email, password } = req.body;

      // Password validation — length + upper bound
      if (!password || password.length < 8) {
        return res.status(400).json({ error: "Password must be at least 8 characters" });
      }
      if (password.length > 128) {
        return res.status(400).json({ error: "Password is too long" });
      }
      if (!email || !email.includes("@")) {
        return res.status(400).json({ error: "Valid email is required" });
      }

      const bcrypt       = require("bcryptjs");
      const passwordHash = await bcrypt.hash(password, 12);

      // Check token is still valid and not expired
      const check = await db.query(
        `SELECT id FROM api_keys
         WHERE invite_token = $1
           AND status = 'pending'
           AND invite_expires_at > NOW()`,
        [req.params.token]
      );

      if (!check.rows.length) {
        // Distinguish expired from invalid
        const expired = await db.query(
          `SELECT id FROM api_keys
           WHERE invite_token = $1
             AND status = 'pending'
             AND invite_expires_at <= NOW()`,
          [req.params.token]
        );

        if (expired.rows.length) {
          return res.status(410).json({
            error: "This invite link has expired — ask an admin to send a new one",
          });
        }

        return res.status(404).json({ error: "Invalid or already-used invite token" });
      }

      // Set email + password
      await db.query(
        `UPDATE api_keys SET email = $1, password_hash = $2 WHERE id = $3`,
        [email.toLowerCase().trim(), passwordHash, check.rows[0].id]
      );

      // Activate — wipes raw key, sets status = active
      const activated = await km.activateInvite(req.params.token);
      if (!activated) {
        return res.status(404).json({ error: "Activation failed — token may have just expired" });
      }

      res.json({
        message:     "Account activated. Save your API key — it will NOT be shown again.",
        key:         activated.key,
        name:        activated.name,
        role:        activated.role,
        daily_limit: activated.daily_limit,
      });

    } catch (err) {
      console.error("[activate/post] ERROR:", err.message);
      console.error("[activate/post] STACK:", err.stack);
      res.status(500).json({ error: err.message });
    }
  }
);

// GET /api/keys/:id 
router.get("/:id",
  requireAuth, requireRole("admin"),
  [param("id").isInt({ min: 1 })],
  validate,
  async (req, res) => {
    try {
      const key = await km.getKey(parseInt(req.params.id));
      if (!key) return res.status(404).json({ error: "Key not found" });
      res.json({ ...key, key: key.key ? key.key.slice(0, 8) + "••••••••••••••••••••••••" : null });
    } catch (err) {
      console.error("[keys/get]", err.message);
      res.status(500).json({ error: err.message });
    }
  }
);

// PUT /api/keys/:id 
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
      console.error("[keys/update]", err.message);
      res.status(500).json({ error: err.message });
    }
  }
);

// POST /api/keys/:id/revoke 
router.post("/:id/revoke",
  requireAuth, requireRole("admin"),
  [
    param("id").isInt({ min: 1 }),
    body("reason").optional().trim().isLength({ max: 200 }),
  ],
  validate,
  async (req, res) => {
    if (Number(req.auth.id) === Number(req.params.id)) {
      return res.status(400).json({ error: "You cannot revoke your own key" });
    }
    try {
      const ok = await km.revokeKey(parseInt(req.params.id), req.body.reason);
      if (!ok) return res.status(404).json({ error: "Key not found or already revoked" });
      res.json({ message: "Key revoked" });
    } catch (err) {
      console.error("[keys/revoke]", err.message);
      res.status(500).json({ error: err.message });
    }
  }
);

// POST /api/keys/:id/suspend 
router.post("/:id/suspend",
  requireAuth, requireRole("admin"),
  [param("id").isInt({ min: 1 })],
  validate,
  async (req, res) => {
    if (Number(req.auth.id) === Number(req.params.id)) {
      return res.status(400).json({ error: "You cannot suspend your own key" });
    }
    try {
      await km.suspendKey(parseInt(req.params.id));
      res.json({ message: "Key suspended" });
    } catch (err) {
      console.error("[keys/suspend]", err.message);
      res.status(500).json({ error: err.message });
    }
  }
);

// DELETE /api/keys/:id 
router.delete("/:id",
  requireAuth, requireRole("admin"),
  [param("id").isInt({ min: 1 })],
  validate,
  async (req, res) => {
    if (Number(req.auth.id) === Number(req.params.id)) {
      return res.status(400).json({ error: "You cannot delete your own admin key" });
    }
    try {
      const result = await db.query(
        `DELETE FROM api_keys WHERE id = $1 RETURNING id, name`,
        [parseInt(req.params.id)]
      );
      if (!result.rows.length) return res.status(404).json({ error: "Key not found" });
      res.json({ message: `Key "${result.rows[0].name}" permanently deleted` });
    } catch (err) {
      console.error("[keys/delete]", err.message);
      res.status(500).json({ error: err.message });
    }
  }
);

// POST /api/keys/:id/reinstate 
router.post("/:id/reinstate",
  requireAuth, requireRole("admin"),
  [param("id").isInt({ min: 1 })],
  validate,
  async (req, res) => {
    try {
      await km.reinstateKey(parseInt(req.params.id));
      res.json({ message: "Key reinstated" });
    } catch (err) {
      console.error("[keys/reinstate]", err.message);
      res.status(500).json({ error: err.message });
    }
  }
);

// POST /api/keys/:id/rotate 
router.post("/:id/rotate",
  requireAuth, requireRole("admin"),
  [param("id").isInt({ min: 1 })],
  validate,
  async (req, res) => {
    if (Number(req.auth.id) === Number(req.params.id)) {
      return res.status(400).json({ error: "You cannot rotate your own active admin key" });
    }
    try {
      const result = await km.rotateKey(parseInt(req.params.id));
      if (!result) return res.status(404).json({ error: "Key not found or not active" });
      res.json({
        message: "Key rotated. Save the new key — it will not be shown again.",
        newKey:  result.newKey,
        name:    result.name,
      });
    } catch (err) {
      console.error("[keys/rotate]", err.message);
      res.status(500).json({ error: err.message });
    }
  }
);

// GET /api/keys/:id/usage 
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
      res.json({
        key_id: parseInt(req.params.id),
        days:   parseInt(req.query.days || "30"),
        usage,
      });
    } catch (err) {
      console.error("[keys/usage]", err.message);
      res.status(500).json({ error: err.message });
    }
  }
);

// POST /api/keys/me  — create a new API key owned by the logged-in user
router.post("/me",
  requireAuth,
  [
    body("name").trim().notEmpty().isLength({ max: 100 }),
  ],
  validate,
  async (req, res) => {
    if (req.auth.type !== "user") {
      return res.status(403).json({
        error: "user_login_required",
        message: "API keys must be created from a logged-in dashboard account, not another API key.",
      });
    }
 
    try {
      const rawKey   = "ipsk_" + crypto.randomBytes(24).toString("hex");
      const keyHash  = hashKey(rawKey);
      const preview  = rawKey.slice(0, 12) + "…";
 
      // New self-serve keys inherit the readonly/analyst default — admins can
      // still elevate role via PUT /:id same as any other key.
      const result = await db.query(
        `INSERT INTO api_keys (name, role, status, key_hash, key_preview, user_id, activated_at)
         VALUES ($1, 'analyst', 'active', $2, $3, $4, NOW())
         RETURNING id, name, role, status, created_at`,
        [req.body.name, keyHash, preview, req.auth.id]
      );
 
      res.status(201).json({
        message: "API key created. Save it now — it will not be shown again.",
        key:     rawKey,
        id:      result.rows[0].id,
        name:    result.rows[0].name,
        role:    result.rows[0].role,
      });
    } catch (err) {
      console.error("[keys/self-create]", err.message);
      res.status(500).json({ error: err.message });
    }
  }
);
 
// GET /api/keys/me/list — list keys owned by the logged-in user (not admin-only)
router.get("/me/list", requireAuth, async (req, res) => {
  if (req.auth.type !== "user") {
    return res.status(403).json({ error: "user_login_required" });
  }
  try {
    const result = await db.query(
      `SELECT id, name, role, status, key_preview, created_at, last_used, daily_limit, daily_used
       FROM api_keys WHERE user_id = $1 ORDER BY created_at DESC`,
      [req.auth.id]
    );
    res.json({ keys: result.rows });
  } catch (err) {
    console.error("[keys/me/list]", err.message);
    res.status(500).json({ error: err.message });
  }
});
 

module.exports = router;