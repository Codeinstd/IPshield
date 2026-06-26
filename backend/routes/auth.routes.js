const express   = require("express");
const router    = express.Router();
const bcrypt    = require("bcryptjs");
const jwt       = require("jsonwebtoken");
const rateLimit = require("express-rate-limit");
const db        = require("../store/db");
const { hashKey } = require("../utils/keyHash");
const crypto = require("crypto");
const { sendEmail } = require("../services/email.service");


// Rate limiters 
const loginLimiter = rateLimit({
  windowMs:        15 * 60 * 1000, // 15 minutes
  max:             10,              // 10 attempts per IP
  standardHeaders: true,
  legacyHeaders:   false,
  message:         { error: "Too many login attempts — try again in 15 minutes" },
  // Skip successful requests so only failures count toward the limit
  skipSuccessfulRequests: true,
});

const mfaLimiter = rateLimit({
  windowMs:        5 * 60 * 1000,  // 5 minutes (matches challenge token TTL)
  max:             10,
  standardHeaders: true,
  legacyHeaders:   false,
  message:         { error: "Too many MFA attempts — please log in again" },
  skipSuccessfulRequests: true,
});

const resetLimiter = rateLimit({
  windowMs:        15 * 60 * 1000, // 15 minutes
  max:             5,               // 5 attempts per IP
  standardHeaders: true,
  legacyHeaders:   false,
  message:         { error: "Too many reset attempts — try again in 15 minutes" },
});

// POST /api/v1/auth/login 
router.post("/login", loginLimiter, async (req, res) => {
  try {
    const { email, password, apiKey } = req.body;

    //API key login 
    if (apiKey) {
      const keyHash = hashKey(apiKey);

      const result = await db.query(
        `SELECT id, name, email, role, status FROM api_keys WHERE key_hash = $1`,
        [keyHash]
      );

      if (!result.rows.length) {
        return res.status(401).json({ error: "Invalid API key" });
      }

      const key = result.rows[0];

      if (key.status !== "active") {
        return res.status(403).json({ error: `Account is ${key.status}` });
      }

      const token = jwt.sign(
        { id: key.id, name: key.name, email: key.email, role: key.role },
        process.env.JWT_SECRET,
        { expiresIn: "7d" }
      );

      return res.json({
        token,
        user: { id: key.id, name: key.name, email: key.email, role: key.role },
      });
    }

    // Email + password login 
    if (email && password) {
          const result = await db.query(
          `SELECT id, email, role, password_hash, mfa_enabled, mfa_secret
          FROM users
          WHERE LOWER(email) = LOWER($1)`,
          [email.trim()]
        );
    

      if (!result.rows.length) {
        return res.status(401).json({ error: "Invalid email or password" });
      }

      const user = result.rows[0];

      if (!user.password_hash) {
        return res.status(401).json({
          error: "Password not set — use your activation link to set a password first",
        });
      }

      const isValid = await bcrypt.compare(password, user.password_hash);
      if (!isValid) {
        return res.status(401).json({ error: "Invalid email or password" });
      }

      // Force MFA enrolment for accounts that haven't set it up
      if (!user.mfa_enabled) {
        const setupToken = jwt.sign(
          { id: user.id, email: user.email, role: user.role, mfaSetup: true },
          process.env.JWT_SECRET,
          { expiresIn: "15m" }
        );

        return res.status(200).json({
          mfaSetupRequired: true,
          token: setupToken,
          user: { id: user.id, email: user.email, role: user.role },
        });
      }

      // Issue short-lived challenge — TOTP submitted to /login/mfa separately
      const challengeToken = jwt.sign(
        { id: user.id, mfaChallenge: true },
        process.env.JWT_SECRET,
        { expiresIn: "5m" }
      );

      return res.status(200).json({ mfaRequired: true, challengeToken });
    }

    return res.status(400).json({ error: "Provide apiKey or email + password" });

  } catch (err) {
    console.error("[auth/login] ERROR:", err.message);
    console.error("[auth/login] STACK:", err.stack);
    res.status(500).json({ error: "Login failed", detail: err.message });
  }
});

// POST /api/v1/auth/login/mfa 
router.post("/login/mfa", mfaLimiter, async (req, res) => {
  try {
    const { challengeToken, totpToken } = req.body;

    if (!challengeToken || !totpToken) {
      return res.status(400).json({ error: "challengeToken and totpToken required" });
    }

    let decoded;
    try {
      decoded = jwt.verify(challengeToken, process.env.JWT_SECRET);
    } catch (_) {
      return res.status(401).json({ error: "Challenge expired — please log in again" });
    }

    if (!decoded.mfaChallenge) {
      return res.status(400).json({ error: "Invalid challenge token" });
    }

    const result = await db.query(
      `SELECT id, email, role, mfa_secret, mfa_backup_codes
       FROM users
       WHERE id = $1`,
      [decoded.id]
    );

    if (!result.rows.length) {
      return res.status(401).json({ error: "User not found" });
    }

    const user = result.rows[0];
    const { verifyToken } = require("../services/mfa.service");

    const rawInput = String(totpToken).trim().toUpperCase();

    // 1. Try TOTP 
    let valid = verifyToken(rawInput, user.mfa_secret);

    // 2. Try backup codes 
    if (!valid && Array.isArray(user.mfa_backup_codes) && user.mfa_backup_codes.length) {
      for (let i = 0; i < user.mfa_backup_codes.length; i++) {
        const match = await bcrypt.compare(rawInput, user.mfa_backup_codes[i]);

        if (match) {
          // Consume — remove used code from array
          const remaining = user.mfa_backup_codes.filter((_, idx) => idx !== i);
          await db.query(
            `UPDATE users SET mfa_backup_codes = $1 WHERE id = $2`,
            [remaining, user.id]
          );
          valid = true;
          break;
        }
      }
    }

    if (!valid) {
      return res.status(401).json({ error: "Invalid authenticator code or backup code" });
    }

    const token = jwt.sign(
      { id: user.id, email: user.email, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.json({
      token,
      user: { id: user.id, email: user.email, role: user.role },
    });

  } catch (err) {
    console.error("[auth/login/mfa]", err.message);
    res.status(500).json({ error: "MFA verification failed" });
  }
});

// POST /api/v1/auth/logout 
router.post("/logout", (_req, res) => {
  res.json({ message: "Logged out" });
});

// GET /api/v1/auth/me 
router.get("/me", (req, res) => {
  const token = (req.headers.authorization || "").replace("Bearer ", "");
  if (!token) return res.status(401).json({ error: "No token" });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    res.json({ id: decoded.id, name: decoded.name, email: decoded.email, role: decoded.role });
  } catch {
    res.status(401).json({ error: "Invalid or expired token" });
  }
});

// POST /api/v1/auth/forgot-password 
router.post("/forgot-password", resetLimiter, async (req, res) => {
  try {
    const { email } = req.body;

    if (!email || !email.includes("@")) {
      return res.status(400).json({ error: "Valid email is required" });
    }

    const result = await db.query(
      `SELECT id, email FROM api_keys
        WHERE LOWER(email) = LOWER($1)`,
      [email.trim()]
    );

    // Always respond the same way — don't reveal if email exists
    if (!result.rows.length) {
      return res.json({ ok: true });
    }

    const user  = result.rows[0];
    const token = crypto.randomBytes(32).toString("hex");
    const expires = new Date(Date.now() + 60 * 60 * 1000); // 1 hour

    // Store hashed token — never store raw token in DB
    const tokenHash = crypto.createHash("sha256").update(token).digest("hex");

    await db.query(
      `UPDATE users
       SET reset_token = $1, reset_token_expires = $2
       WHERE id = $3`,
      [tokenHash, expires, user.id]
    );

    const baseUrl  = process.env.APP_URL || "https://ipshield.live";
    const resetUrl = `${baseUrl}/reset-password?token=${token}`;

    // Fire and forget — don't block response on email delivery
    sendEmail({
      to:      user.email,
      subject: "[IPShield] Reset your password",
      html: `
        <div style="background:#0d1117;padding:32px;font-family:monospace;
                    max-width:520px;margin:0 auto;">
          <h2 style="color:#c9d8e8;margin-bottom:8px;">
            IP<span style="color:#00d9ff;">Shield</span> — Password Reset
          </h2>
          <p style="color:#6a8fa8;font-size:13px;margin-bottom:24px;">
            Hi ${user.email}, we received a request to reset your password.
          </p>
          <p style="margin-bottom:24px;">
            <a href="${resetUrl}"
               style="background:#02bfe0;color:#000;padding:12px 28px;
                      border-radius:6px;text-decoration:none;font-weight:700;
                      font-size:13px;">
              Reset Password →
            </a>
          </p>
          <p style="font-size:12px;color:#6a8fa8;margin-bottom:8px;">
            Or copy this link:<br>
            <code style="color:#02bfe0;word-break:break-all;">${resetUrl}</code>
          </p>
          <p style="font-size:11px;color:#3d5a72;border-top:1px solid #1e2d3d;
                    padding-top:16px;margin-top:16px;">
            This link expires in 1 hour. If you didn't request this, 
            you can safely ignore this email — your password won't change.
          </p>
        </div>`,
    }).catch(err => console.error("[forgot-password/email]", err.message));

    res.json({ ok: true });

  } catch (err) {
    console.error("[forgot-password]", err.message);
    res.status(500).json({ error: "Reset request failed" });
  }
});

// POST /api/v1/auth/reset-password 
router.post("/reset-password", resetLimiter, async (req, res) => {
  try {
    const { token, password } = req.body;

    if (!token) {
      return res.status(400).json({ error: "Reset token is required" });
    }
    if (!password || password.length < 8) {
      return res.status(400).json({ error: "Password must be at least 8 characters" });
    }
    if (password.length > 128) {
      return res.status(400).json({ error: "Password is too long" });
    }

    // Hash the incoming token to compare against DB
    const tokenHash = crypto.createHash("sha256").update(token).digest("hex");

    const result = await db.query(
      `SELECT id, email FROM users
       WHERE reset_token = $1
         AND reset_token_expires > NOW()`,
      [tokenHash]
    );

    if (!result.rows.length) {
      return res.status(400).json({
        error: "Reset link is invalid or has expired — request a new one",
      });
    }

    const user         = result.rows[0];
    const passwordHash = await bcrypt.hash(password, 12);

    // Update password and clear the reset token atomically
    await db.query(
      `UPDATE users
       SET password_hash        = $1,
           reset_token          = NULL,
           reset_token_expires  = NULL
       WHERE id = $2`,
      [passwordHash, user.id]
    );

    console.log(`[reset-password] Password reset for: ${user.email}`);

    res.json({ ok: true, message: "Password updated — you can now sign in" });

  } catch (err) {
    console.error("[reset-password]", err.message);
    res.status(500).json({ error: "Password reset failed" });
  }
});

module.exports = router;