const express   = require("express");
const router    = express.Router();
const bcrypt    = require("bcryptjs");
const jwt       = require("jsonwebtoken");
const rateLimit = require("express-rate-limit");
const db        = require("../store/db");
const { hashKey } = require("../utils/keyHash");

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

// POST /api/v1/auth/login 
router.post("/login", loginLimiter, async (req, res) => {
  try {
    const { email, password, apiKey } = req.body;

    // ── API key login ──────────────────────────────────────────────────────────
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

    // ── Email + password login ─────────────────────────────────────────────────
    if (email && password) {
      const result = await db.query(
        `SELECT id, name, email, role, status, password_hash, mfa_enabled, mfa_secret
         FROM api_keys
         WHERE LOWER(email) = LOWER($1)
           AND status = 'active'`,
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
          { id: user.id, email: user.email, name: user.name, role: user.role, mfaSetup: true },
          process.env.JWT_SECRET,
          { expiresIn: "15m" }
        );

        return res.status(200).json({
          mfaSetupRequired: true,
          token: setupToken,
          user: { id: user.id, email: user.email, name: user.name, role: user.role },
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
      `SELECT id, name, email, role, status, mfa_secret, mfa_backup_codes
       FROM api_keys
       WHERE id = $1 AND status = 'active'`,
      [decoded.id]
    );

    if (!result.rows.length) {
      return res.status(401).json({ error: "User not found" });
    }

    const user = result.rows[0];
    const { verifyToken } = require("../services/mfa.service");

    const rawInput = String(totpToken).trim().toUpperCase();

    // ── 1. Try TOTP ───────────────────────────────────────────────────────────
    let valid = verifyToken(rawInput, user.mfa_secret);

    // ── 2. Try backup codes ───────────────────────────────────────────────────
    if (!valid && Array.isArray(user.mfa_backup_codes) && user.mfa_backup_codes.length) {
      for (let i = 0; i < user.mfa_backup_codes.length; i++) {
        const match = await bcrypt.compare(rawInput, user.mfa_backup_codes[i]);

        if (match) {
          // Consume — remove used code from array
          const remaining = user.mfa_backup_codes.filter((_, idx) => idx !== i);
          await db.query(
            `UPDATE api_keys SET mfa_backup_codes = $1 WHERE id = $2`,
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
      { id: user.id, name: user.name, email: user.email, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.json({
      token,
      user: { id: user.id, name: user.name, email: user.email, role: user.role },
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

module.exports = router;