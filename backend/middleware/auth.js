
const {query} = require('../db.js');
 
const ROLE_RANK = { readonly: 0, analyst: 1, admin: 2 };
 
// Simple in-process cache: key string → { id, name, role } for 5 minutes
const KEY_CACHE = new Map();
const CACHE_TTL_MS = 5 * 60 * 1000;
 
async function resolveKey(rawKey) {
  const cached = KEY_CACHE.get(rawKey);
  if (cached && Date.now() - cached.ts < CACHE_TTL_MS) {
    return cached.data;
  }
 
  const { rows } = await query(
    `UPDATE api_keys
     SET last_used = NOW()
     WHERE key = $1
     RETURNING id, name, role`,
    [rawKey]
  );
 
  if (!rows.length) return null;
 
  const data = rows[0];
  KEY_CACHE.set(rawKey, { data, ts: Date.now() });
  return data;
}
 
/**
 * requireAuth middleware
 * Reads x-api-key header, looks it up in Postgres, attaches req.apiKey.
 * Returns 401 if missing, 403 if not found.
 */
export async function requireAuth(req, res, next) {
  const rawKey = req.headers['x-api-key'];
 
  if (!rawKey) {
    return res.status(401).json({
      error: 'Unauthorized',
      message: 'Missing x-api-key header',
    });
  }
 
  try {
    const apiKey = await resolveKey(rawKey);
    if (!apiKey) {
      return res.status(403).json({
        error: 'Forbidden',
        message: 'Invalid API key',
      });
    }
    req.apiKey = apiKey;
    next();
  } catch (err) {
    console.error('[auth] DB error during key lookup:', err.message);
    return res.status(500).json({ error: 'Internal error during authentication' });
  }
}
 
/**
 * requireRole(minimumRole) → Express middleware
 * Must be placed AFTER requireAuth so req.apiKey is populated.
 *
 * Example:  requireRole('admin')  — only admins may proceed
 *           requireRole('analyst') — analysts and admins may proceed
 */
export function requireRole(minimumRole) {
  const minRank = ROLE_RANK[minimumRole];
  if (minRank === undefined) {
    throw new Error(`requireRole: unknown role "${minimumRole}". Valid: ${Object.keys(ROLE_RANK).join(', ')}`);
  }
 
  return function roleGuard(req, res, next) {
    const keyRole = req.apiKey?.role ?? 'readonly';
    const keyRank = ROLE_RANK[keyRole] ?? 0;
 
    if (keyRank < minRank) {
      return res.status(403).json({
        error: 'Forbidden',
        message: `This action requires the "${minimumRole}" role. Your key has role "${keyRole}".`,
      });
    }
    next();
  };
}
 
/** Clear the in-process key cache (useful in tests) */
export function clearKeyCache() {
  KEY_CACHE.clear();
}