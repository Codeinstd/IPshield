const express  = require("express");
const router   = express.Router();
const db       = require("../store/db");                    
const { requireAuth, requireRole } = require("../middleware/auth.js");

// GET /api/v2/gdpr/export?email=user@company.com
router.get("/export", requireAuth, requireRole("admin"), async (req, res) => {
  try {
    const { email } = req.query;
    if (!email) return res.status(400).json({ error: "email required" });

    const [keyData, usageData] = await Promise.all([
      db.query(
        `SELECT id, name, email, role, status, daily_limit,
                invited_at, activated_at, last_used, notes
         FROM api_keys WHERE LOWER(email) = LOWER($1)`,
        [email]
      ),
      db.query(
        `SELECT date, requests, scores, cache_hits, errors
         FROM key_usage_log
         WHERE key_id = (SELECT id FROM api_keys WHERE LOWER(email) = LOWER($1))
         ORDER BY date DESC`,
        [email]
      ),
    ]);

    if (!keyData.rows.length) {
      return res.status(404).json({ error: "No account found for that email" });
    }

    res.json({
      exported_at: new Date().toISOString(),
      subject:     email,
      account:     keyData.rows[0],
      usage:       usageData.rows,
    });

  } catch (err) {
    console.error("[gdpr/export]", err.message);
    res.status(500).json({ error: err.message });
  }
});

// DELETE /api/v2/gdpr/erase?email=user@company.com
router.delete("/erase", requireAuth, requireRole("admin"), async (req, res) => {
  try {
    const { email } = req.query;
    if (!email) return res.status(400).json({ error: "email required" });

    const result = await db.query(
      `UPDATE api_keys
       SET email         = NULL,
           name          = 'Deleted User',
           password_hash = NULL,
           mfa_secret    = NULL,
           mfa_backup_codes = NULL,
           mfa_enabled   = FALSE,
           reset_token   = NULL,
           notes         = NULL,
           status        = 'revoked',
           revoked_at    = NOW(),
           revoke_reason = 'GDPR erasure request'
       WHERE LOWER(email) = LOWER($1)
       RETURNING id`,
      [email]
    );

    if (!result.rows.length) {
      return res.status(404).json({ error: "No account found for that email" });
    }

    res.json({
      message:    "Personal data erased",
      account_id: result.rows[0].id,
      erased_at:  new Date().toISOString(),
    });

  } catch (err) {
    console.error("[gdpr/erase]", err.message);
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;