const express  = require("express");
const router   = express.Router();
const db       = require("../store/db");
const { requireAuth }                      = require("../middleware/auth.js");
const { generateSecret, generateQR, verifyToken } = require("../services/mfa.service.js");
const { generateBackupCodes, hashBackupCodes }    = require("../services/backupCodes.service");

// GET /api/v1/mfa/setup 
// Generate a new secret + QR for the current user.
router.get("/setup", requireAuth, async (req, res) => {
  try {
    const userId = req.auth.id;

    const existing = await db.query(
      `SELECT mfa_enabled, email, name FROM api_keys WHERE id = $1`,
      [userId]
    );

    if (!existing.rows.length) {
      return res.status(404).json({ error: "User not found" });
    }

    const user = existing.rows[0];

    if (user.mfa_enabled) {
      return res.status(400).json({ error: "MFA is already enabled" });
    }

    const { secret, otpauth } = generateSecret(user.email || user.name);
    const qrDataUrl = await generateQR(otpauth);

    // Store secret temporarily — NOT enabled until /verify-setup succeeds
    await db.query(
      `UPDATE api_keys SET mfa_secret = $1 WHERE id = $2`,
      [secret, userId]
    );

    res.json({
      secret,
      qrCode:  qrDataUrl,
      message: "Scan the QR code with your authenticator app, then verify with a 6-digit code",
    });
  } catch (err) {
    console.error("[mfa/setup]", err.message);
    res.status(500).json({ error: "MFA setup failed" });
  }
});

// POST /api/v1/mfa/verify-setup 
// Confirm a TOTP code against the pending secret and fully enable MFA.
// Returns plain-text backup codes exactly once — user must save them.
router.post("/verify-setup", requireAuth, async (req, res) => {
  try {
    const { token } = req.body;
    const userId    = req.auth.id;

    if (!token) {
      return res.status(400).json({ error: "Verification code required" });
    }

    const result = await db.query(
      `SELECT mfa_secret, mfa_enabled FROM api_keys WHERE id = $1`,
      [userId]
    );

    if (!result.rows.length || !result.rows[0].mfa_secret) {
      return res.status(400).json({ error: "No MFA setup in progress — call /setup first" });
    }

    const { mfa_secret, mfa_enabled } = result.rows[0];

    if (mfa_enabled) {
      return res.status(400).json({ error: "MFA is already enabled" });
    }

    const valid = verifyToken(token, mfa_secret);
    if (!valid) {
      return res.status(401).json({ error: "Invalid code — check your authenticator app and try again" });
    }

    const backupCodes = generateBackupCodes();        // 8 plain-text codes
    const hashedCodes = await hashBackupCodes(backupCodes); // stored hashed

    await db.query(
      `UPDATE api_keys
       SET mfa_enabled      = TRUE,
           mfa_verified_at  = NOW(),
           mfa_backup_codes = $2
       WHERE id = $1`,
      [userId, hashedCodes]
    );

    // Plain-text codes returned ONCE — never stored in this form
    res.json({
      message:     "MFA enabled successfully",
      backupCodes, // e.g. ["A3F2C9B1", "D4E5F6A7", ...]
    });

  } catch (err) {
    console.error("[mfa/verify-setup]", err.message);
    res.status(500).json({ error: "Verification failed" });
  }
});

// POST /api/v1/mfa/disable 
// Disable MFA — requires a valid current TOTP code.
// Clears secret, backup codes, and verified_at.
router.post("/disable", requireAuth, async (req, res) => {
  try {
    const { token } = req.body;
    const userId    = req.auth.id;

    if (!token) {
      return res.status(400).json({ error: "Current MFA code required to disable" });
    }

    const result = await db.query(
      `SELECT mfa_secret, mfa_enabled FROM api_keys WHERE id = $1`,
      [userId]
    );

    if (!result.rows.length) {
      return res.status(404).json({ error: "User not found" });
    }

    const { mfa_secret, mfa_enabled } = result.rows[0];

    if (!mfa_enabled) {
      return res.status(400).json({ error: "MFA is not currently enabled" });
    }

    const valid = verifyToken(token, mfa_secret);
    if (!valid) {
      return res.status(401).json({ error: "Invalid code" });
    }

    // FIX: also clear mfa_backup_codes — previously left orphaned in DB
    await db.query(
      `UPDATE api_keys
       SET mfa_enabled      = FALSE,
           mfa_secret       = NULL,
           mfa_verified_at  = NULL,
           mfa_backup_codes = NULL
       WHERE id = $1`,
      [userId]
    );

    res.json({ message: "MFA disabled" });

  } catch (err) {
    console.error("[mfa/disable]", err.message);
    res.status(500).json({ error: "Failed to disable MFA" });
  }
});

// GET /api/v1/mfa/status 
router.get("/status", requireAuth, async (req, res) => {
  try {
    const result = await db.query(
      `SELECT mfa_enabled, mfa_verified_at FROM api_keys WHERE id = $1`,
      [req.auth.id]
    );
    if (!result.rows.length) {
      return res.status(404).json({ error: "User not found" });
    }
    res.json({
      enabled:    result.rows[0].mfa_enabled    || false,
      verifiedAt: result.rows[0].mfa_verified_at || null,
    });
  } catch (err) {
    console.error("[mfa/status]", err.message);
    res.status(500).json({ error: "Failed to get MFA status" });
  }
});

module.exports = router;