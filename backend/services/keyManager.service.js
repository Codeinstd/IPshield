
const crypto = require("crypto");
const { hashKey } = require("../utils/keyHash");
const db     = require("../store/db");
const logger = require("../utils/logger");

// Helpers 

function generateKey() {
  return crypto.randomBytes(32).toString("hex");
}

function generateInviteToken() {
  return crypto.randomBytes(24).toString("hex");
}

// Create invite 
async function createInvite({ name, email, role = "analyst", dailyLimit = 1000, notes, invitedBy = "admin" }) {
  const key         = generateKey();
  const keyHash     = hashKey(key);
  const keyPreview  = key.slice(0, 8) + "••••••••••••••••";
  const inviteToken = generateInviteToken();

  await db.query(
    `INSERT INTO api_keys
       (key_hash, key, key_preview, name, email, role, status,
        invite_token, invited_by, invited_at, daily_limit, notes)
     VALUES ($1,$2,$3,$4,$5,$6,'pending',$7,$8,NOW(),$9,$10)`,
    [keyHash, key, keyPreview, name, email || null, role,
     inviteToken, invitedBy, dailyLimit, notes || null]
  );

  const invite = await db.query(
    `SELECT id, name, email, role, status, daily_limit, invite_token
     FROM api_keys WHERE key_hash = $1`,
    [keyHash]
  );

  const baseUrl     = process.env.APP_URL || "https://ipshield.live";
  const activateUrl = `${baseUrl}/activate?token=${inviteToken}`;

  logger.info(`[keyManager] Invite created for ${email || name} by ${invitedBy}`);

  // Return raw key only here — it will be wiped on activation
  return { ...invite.rows[0], activateUrl, rawKey: key, invite_token: inviteToken };
}

// Activate invite 
async function activateInvite(inviteToken) {
  const client = await db.pool.connect();   
  try {
    await client.query("BEGIN");

    // Activate the invite
    const activateRes = await client.query(
      `UPDATE api_keys
       SET status = 'active', activated_at = NOW(), invite_token = NULL
       WHERE invite_token = $1 AND status = 'pending'
       RETURNING id, name, email, role, status, activated_at, daily_limit, key`,
      [inviteToken]
    );

    if (!activateRes.rows.length) {
      await client.query("ROLLBACK");
      return null;
    }

    const row = activateRes.rows[0];
    const rawKey = row.key; 

    // Wipe raw key from DB it exits as hash
    await client.query(
      `UPDATE api_keys SET key = NULL WHERE id = $1`,
      [row.id]
    );

    await client.query("COMMIT");

    logger.info(`[keyManager] Key activated and raw key wiped: ${row.name}`);

    // Return raw key in response — this is the ONLY time it's available
    return { ...row, key: rawKey };

  } catch (err) {
    await client.query("ROLLBACK");
    logger.error("[keyManager] activateInvite transaction failed:", err.message);
    throw err;
  } finally {
    client.release();
  }
}

// List keys
async function listKeys({ status, role, limit = 100, offset = 0 } = {}) {
  const conditions = [];
  const values     = [];
  let   idx        = 1;

  if (status) { conditions.push(`status = $${idx++}`); values.push(status); }
  if (role)   { conditions.push(`role   = $${idx++}`); values.push(role);   }

  const where = conditions.length ? `WHERE ${conditions.join(" AND ")}` : "";

  const sql = `
    SELECT
      id,
      name,
      email,
      role,
      status,
      COALESCE(key_preview, '(not set)')        AS key_preview,
      daily_limit,
      COALESCE(daily_used, 0)                   AS daily_used,
      notes,
      last_used,
      invited_at,
      activated_at,
      revoked_at,
      revoke_reason
    FROM api_keys
    ${where}
    ORDER BY
      CASE status
        WHEN 'active'    THEN 1
        WHEN 'pending'   THEN 2
        WHEN 'suspended' THEN 3
        WHEN 'revoked'   THEN 4
        ELSE 5
      END,
      invited_at DESC NULLS LAST
    LIMIT  $${idx++}
    OFFSET $${idx++}
  `;
  values.push(limit, offset);

  const result = await db.query(sql, values);

  const countSql = `SELECT COUNT(*) FROM api_keys ${where}`;
  const countRes = await db.query(countSql, values.slice(0, -2));

  return {
    keys:  result.rows,
    total: parseInt(countRes.rows[0].count),
  };
}

// Get single key (admin — includes full key) 
async function getKey(id) {
  const res = await db.query(
    `SELECT id, name, email, role, status, key, daily_limit, daily_used,
            total_used, invited_by, invited_at, activated_at,
            revoked_at, revoke_reason, last_used, notes
     FROM api_keys WHERE id = $1`,
    [id]
  );
  return res.rows[0] || null;
}

// Update key 
async function updateKey(id, { name, email, role, dailyLimit, notes }) {
  const sets   = [];
  const params = [];
  let   i      = 1;

  if (name       !== undefined) { sets.push(`name = $${i++}`);        params.push(name); }
  if (email      !== undefined) { sets.push(`email = $${i++}`);       params.push(email); }
  if (role       !== undefined) { sets.push(`role = $${i++}`);        params.push(role); }
  if (dailyLimit !== undefined) { sets.push(`daily_limit = $${i++}`); params.push(dailyLimit); }
  if (notes      !== undefined) { sets.push(`notes = $${i++}`);       params.push(notes); }

  if (!sets.length) return getKey(id);

  params.push(id);
  const res = await db.query(
    `UPDATE api_keys SET ${sets.join(", ")} WHERE id = $${i} RETURNING *`,
    params
  );
  return res.rows[0] || null;
}

// Revoke key 
async function revokeKey(id, reason = "Revoked by admin") {
  const res = await db.query(
    `UPDATE api_keys
     SET status = 'revoked', revoked_at = NOW(), revoke_reason = $1
     WHERE id = $2 AND status != 'revoked'
     RETURNING id, name, email`,
    [reason, id]
  );
  if (res.rows.length) logger.info(`[keyManager] Key revoked: ${res.rows[0].name} — ${reason}`);
  return res.rows.length > 0;
}

// Suspend / reinstate 
async function suspendKey(id) {
  await db.query(
    `UPDATE api_keys SET status = 'suspended' WHERE id = $1 AND status = 'active'`,
    [id]
  );
}

async function reinstateKey(id) {
  await db.query(
    `UPDATE api_keys SET status = 'active' WHERE id = $1 AND status = 'suspended'`,
    [id]
  );
}

// Rotate key (generate new key value, keep metadata) 
async function rotateKey(id) {
  const newKey     = generateKey();
  const newHash    = hashKey(newKey);
  const newPreview = newKey.slice(0, 8) + "••••••••••••••••";

  const res = await db.query(
    `UPDATE api_keys
     SET key_hash    = $1,
         key_preview = $2,
         key         = NULL,
         last_used   = NULL
     WHERE id = $3 AND status = 'active'
     RETURNING id, name, email`,
    [newHash, newPreview, id]
  );
  if (!res.rows.length) return null;
  logger.info(`[keyManager] Key rotated: ${res.rows[0].name}`);
  return { ...res.rows[0], newKey };
}

// Usage tracking 
async function recordUsage(keyId, { isScore = false, isCacheHit = false, isError = false } = {}) {
  try {
    // Reset daily counter if it's a new day
    await db.query(
      `UPDATE api_keys
       SET daily_used = 0, last_reset = CURRENT_DATE
       WHERE id = $1 AND last_reset < CURRENT_DATE`,
      [keyId]
    );

    // Increment counters
    await db.query(
      `UPDATE api_keys
       SET daily_used = daily_used + 1,
           total_used = total_used + 1,
           last_used  = NOW()
       WHERE id = $1`,
      [keyId]
    );

    // Upsert daily log
    await db.query(
      `INSERT INTO key_usage_log (key_id, date, requests, scores, cache_hits, errors)
       VALUES ($1, CURRENT_DATE, 1, $2, $3, $4)
       ON CONFLICT (key_id, date) DO UPDATE SET
         requests   = key_usage_log.requests   + 1,
         scores     = key_usage_log.scores     + $2,
         cache_hits = key_usage_log.cache_hits + $3,
         errors     = key_usage_log.errors     + $4`,
      [keyId,
       isScore    ? 1 : 0,
       isCacheHit ? 1 : 0,
       isError    ? 1 : 0]
    );
  } catch (_) {
    // Never let usage tracking crash a request
  }
}

// Check daily limit
async function checkDailyLimit(keyId) {
  const res = await db.query(
    `SELECT daily_used, daily_limit, last_reset FROM api_keys WHERE id = $1`,
    [keyId]
  );
  if (!res.rows.length) return { allowed: false };

  const { daily_used, daily_limit, last_reset } = res.rows[0];

  // Reset if new day
  if (last_reset < new Date().toISOString().slice(0, 10)) {
    return { allowed: true, used: 0, limit: daily_limit, remaining: daily_limit };
  }

  const remaining = daily_limit - daily_used;
  return {
    allowed:   remaining > 0,
    used:      daily_used,
    limit:     daily_limit,
    remaining: Math.max(0, remaining),
  };
}

// Usage stats for a key 
async function getKeyUsage(keyId, days = 30) {
  const res = await db.query(
    `SELECT date, requests, scores, cache_hits, errors
     FROM key_usage_log
     WHERE key_id = $1 AND date >= CURRENT_DATE - ($2 || ' days')::INTERVAL
     ORDER BY date DESC`,
    [keyId, days]
  );
  return res.rows;
}

// Reset daily counters (call from a nightly cron)

async function resetDailyCounters() {
  await db.query(
    `UPDATE api_keys
     SET daily_used = 0, last_reset = CURRENT_DATE
     WHERE last_reset < CURRENT_DATE`
  );
  logger.info("[keyManager] Daily counters reset");
}

// Summary stats for admin dashboard 
async function getKeyStats() {
  const result = await db.query(`
    SELECT
      COUNT(*)                                        AS total,
      COUNT(*) FILTER (WHERE status = 'active')      AS active,
      COUNT(*) FILTER (WHERE status = 'pending')     AS pending,
      COUNT(*) FILTER (WHERE status = 'suspended')   AS suspended,
      COUNT(*) FILTER (WHERE status = 'revoked')     AS revoked,
      COALESCE(SUM(COALESCE(daily_used, 0))
        FILTER (WHERE DATE(COALESCE(last_used, NOW())) = CURRENT_DATE), 0)
                                                     AS requests_today,
      COALESCE(SUM(COALESCE(daily_used, 0)), 0)      AS total_requests
    FROM api_keys
  `);

  const row = result.rows[0];
  return {
    total:          parseInt(row.total),
    active:         parseInt(row.active),
    pending:        parseInt(row.pending),
    suspended:      parseInt(row.suspended),
    revoked:        parseInt(row.revoked),
    requestsToday:  parseInt(row.requests_today),
    totalRequests:  parseInt(row.total_requests),
  };
}

module.exports = {
  createInvite, 
  activateInvite,
  listKeys, 
  getKey, 
  updateKey, 
  revokeKey, 
  suspendKey, 
  reinstateKey, 
  rotateKey,
  recordUsage, 
  checkDailyLimit, 
  getKeyUsage, 
  resetDailyCounters, 
  getKeyStats,
};