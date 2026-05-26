
const db = require('../store/db');

const ROLE_RANK = { readonly: 0, analyst: 1, admin: 2 };

// Simple 5-minute in-process cache so we don't hit the DB on every request
const KEY_CACHE = new Map();
const CACHE_TTL_MS = 5 * 60 * 1000;

async function resolveKey(rawKey) {
  const cached = KEY_CACHE.get(rawKey);
  if (cached && Date.now() - cached.ts < CACHE_TTL_MS) {
    return cached.data;
  }
  
const result = await db.query(
  `UPDATE api_keys SET last_used = NOW()
   WHERE key = $1
   RETURNING id, name, role`,
  [rawKey]
);


if (!result || !result.rows || !result.rows.length) return null;

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
    req.apiKey = apiKey;
    next();
  } catch (err) {
    return res.status(500).json({ error: 'Internal error during authentication' });
  }
}

function requireRole(minimumRole) {
  const minRank = ROLE_RANK[minimumRole];
  if (minRank === undefined) {
    throw new Error(
      `requireRole: unknown role "${minimumRole}". Valid: ${Object.keys(ROLE_RANK).join(', ')}`
    );
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