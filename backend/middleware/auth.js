
const db = require('../store/db');
const { recordUsage, checkDailyLimit } = require('../services/keyManager.service');

const ROLE_RANK = { readonly: 0, analyst: 1, admin: 2 };

const KEY_CACHE     = new Map();
const CACHE_TTL_MS  = 5 * 60 * 1000;

async function resolveKey(rawKey) {
  const cached = KEY_CACHE.get(rawKey);
  if (cached && Date.now() - cached.ts < CACHE_TTL_MS) {
    return cached.data;
  }

  const result = await db.query(
    `UPDATE api_keys SET last_used = NOW()
     WHERE key = $1
     RETURNING id, name, role, status, daily_limit, daily_used, last_reset`,
    [rawKey]
  );

  if (!result.rows.length) return null;

  const data = result.rows[0];
  KEY_CACHE.set(rawKey, { data, ts: Date.now() });
  return data;
}

async function requireAuth(req, res, next) {
  const rawKey = req.headers['x-api-key'];

  if (!rawKey) {
    return res.status(401).json({
      error:   'Unauthorized',
      message: 'Missing x-api-key header',
    });
  }

  try {
    const apiKey = await resolveKey(rawKey);
    if (!apiKey) {
      return res.status(403).json({
        error:   'Forbidden',
        message: 'Invalid API key',
      });
    }

    // ── Status check 
    if (apiKey.status === 'pending') {
      return res.status(403).json({
        error:   'Forbidden',
        message: 'This API key has not been activated yet. Check your invite email.',
      });
    }
    if (apiKey.status === 'revoked') {
      return res.status(403).json({
        error:   'Forbidden',
        message: 'This API key has been revoked.',
      });
    }
    if (apiKey.status === 'suspended') {
      return res.status(403).json({
        error:   'Forbidden',
        message: 'This API key is temporarily suspended. Contact support.',
      });
    }

    // ── Daily limit check 
    const limitCheck = await checkDailyLimit(apiKey.id);
    if (!limitCheck.allowed) {
      return res.status(429).json({
        error:     'rate_limit_exceeded',
        message:   `Daily request limit reached (${limitCheck.limit}/day). Resets at midnight UTC.`,
        limit:     limitCheck.limit,
        used:      limitCheck.used,
        remaining: 0,
        resetsAt:  new Date(new Date().setUTCHours(24, 0, 0, 0)).toISOString(),
      });
    }

    // Attach limit info to response headers
    res.setHeader('X-RateLimit-Limit',     limitCheck.limit);
    res.setHeader('X-RateLimit-Remaining', limitCheck.remaining - 1);
    res.setHeader('X-RateLimit-Reset',     new Date(new Date().setUTCHours(24, 0, 0, 0)).toISOString());

    req.apiKey = apiKey;

    // ── Track usage (non-blocking) 
    const isScore = req.path?.includes('/score');
    recordUsage(apiKey.id, { isScore }).catch(() => {});

    // Invalidate cache entry so daily_used is fresh next request
    KEY_CACHE.delete(rawKey);

    next();
  } catch (err) {
    console.error('[auth] DB error during key lookup:', err.message);
    return res.status(500).json({ error: 'Internal error during authentication' });
  }
}

function requireRole(minimumRole) {
  const minRank = ROLE_RANK[minimumRole];
  if (minRank === undefined) {
    throw new Error(`requireRole: unknown role "${minimumRole}"`);
  }

  return function roleGuard(req, res, next) {
    const keyRole = req.apiKey?.role ?? 'readonly';
    const keyRank = ROLE_RANK[keyRole] ?? 0;

    if (keyRank < minRank) {
      return res.status(403).json({
        error:   'Forbidden',
        message: `This action requires the "${minimumRole}" role. Your key has role "${keyRole}".`,
      });
    }
    next();
  };
}

function clearKeyCache() {
  KEY_CACHE.clear();
}

module.exports = { requireAuth, requireRole, clearKeyCache };