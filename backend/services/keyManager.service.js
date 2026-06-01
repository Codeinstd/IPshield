
const crypto = require("crypto");
const db     = require("../store/db");
const logger = require("../utils/logger");

// ── Helpers 

function generateKey() {
  return crypto.randomBytes(32).toString("hex");
}

function generateInviteToken() {
  return crypto.randomBytes(24).toString("hex");
}

// ── Create invite 

async function createInvite({ name, email, role = "analyst", dailyLimit = 1000, notes, invitedBy = "admin" }) {
  const key         = generateKey();
  const inviteToken = generateInviteToken();

  const res = await db.query(
    `INSERT INTO api_keys
       (key, name, email, role, status, invite_token, invited_by,
        invited_at, daily_limit, notes)
     VALUES ($1,$2,$3,$4,'pending',$5,$6,NOW(),$7,$8)
     RETURNING id, name, email, role, status, invite_token,
               invited_by, invited_at, daily_limit, notes`,
    [key, name, email || null, role, inviteToken, invitedBy, dailyLimit, notes || null]
  );

  const invite = res.rows[0];

  // Build the activation URL
  const baseUrl    = process.env.APP_URL || "https://ipshield.live";
  const activateUrl = `${baseUrl}/api/keys/activate/${inviteToken}`;

  logger.info(`[keyManager] Invite created for ${email || name} by ${invitedBy}`);

  return { ...invite, activateUrl, rawKey: key };
}

// ── Activate invite 

async function activateInvite(inviteToken) {
  const res = await db.query(
    `UPDATE api_keys
     SET status = 'active', activated_at = NOW(), invite_token = NULL
     WHERE invite_token = $1 AND status = 'pending'
     RETURNING id, name, email, role, status, activated_at, daily_limit`,
    [inviteToken]
  );

  if (!res.rows.length) return null;
  logger.info(`[keyManager] Key activated: ${res.rows[0].name}`);
  return res.rows[0];
}

// ── List keys

async function listKeys({ status, role, limit = 100, offset = 0 } = {}) {
  const conds  = [];
  const params = [];
  let   i      = 1;

  if (status) { conds.push(`status = $${i++}`); params.push(status); }
  if (role)   { conds.push(`role = $${i++}`);   params.push(role); }

  const where = conds.length ? `WHERE ${conds.join(" AND ")}` : "";

  const [totalRes, rowsRes] = await Promise.all([
    db.query(`SELECT COUNT(*) AS total FROM api_keys ${where}`, params),
    db.query(
      `SELECT id, name, email, role, status, daily_limit, daily_used,
              total_used, invited_by, invited_at, activated_at,
              revoked_at, revoke_reason, last_used, notes,
              LEFT(key, 8) || '••••••••••••••••••••••••' AS key_preview
       FROM api_keys ${where}
       ORDER BY invited_at DESC NULLS LAST
       LIMIT $${i} OFFSET $${i+1}`,
      [...params, limit, offset]
    ),
  ]);

  return {
    total: parseInt(totalRes.rows[0].total, 10),
    keys:  rowsRes.rows,
  };
}

// ── Get single key (admin — includes full key) 

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

// ── Update key 

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

// ── Revoke key 

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

// ── Suspend / reinstate 

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

// ── Rotate key (generate new key value, keep metadata) 

async function rotateKey(id) {
  const newKey = generateKey();
  const res = await db.query(
    `UPDATE api_keys SET key = $1, last_used = NULL
     WHERE id = $2 AND status = 'active'
     RETURNING id, name, email`,
    [newKey, id]
  );
  if (!res.rows.length) return null;
  logger.info(`[keyManager] Key rotated: ${res.rows[0].name}`);
  return { ...res.rows[0], newKey };
}

// ── Usage tracking 

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

// ── Check daily limit

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

// ── Usage stats for a key 

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

// ── Reset daily counters (call from a nightly cron)

async function resetDailyCounters() {
  await db.query(
    `UPDATE api_keys
     SET daily_used = 0, last_reset = CURRENT_DATE
     WHERE last_reset < CURRENT_DATE`
  );
  logger.info("[keyManager] Daily counters reset");
}

// ── Summary stats for admin dashboard 

async function getKeyStats() {
  const res = await db.query(`
    SELECT
      COUNT(*) FILTER (WHERE status = 'active')    AS active,
      COUNT(*) FILTER (WHERE status = 'pending')   AS pending,
      COUNT(*) FILTER (WHERE status = 'revoked')   AS revoked,
      COUNT(*) FILTER (WHERE status = 'suspended') AS suspended,
      COUNT(*) AS total,
      SUM(total_used) AS total_requests,
      SUM(daily_used) AS requests_today
    FROM api_keys
  `);
  const r = res.rows[0];
  return {
    active:          parseInt(r.active,          10),
    pending:         parseInt(r.pending,         10),
    revoked:         parseInt(r.revoked,         10),
    suspended:       parseInt(r.suspended,       10),
    total:           parseInt(r.total,           10),
    totalRequests:   parseInt(r.total_requests,  10) || 0,
    requestsToday:   parseInt(r.requests_today,  10) || 0,
  };
}

module.exports = {
  createInvite, activateInvite,
  listKeys, getKey, updateKey, revokeKey, suspendKey, reinstateKey, rotateKey,
  recordUsage, checkDailyLimit, getKeyUsage, resetDailyCounters, getKeyStats,
};