
const { getRedis } = require("../store/redis");
const db           = require("../store/db");

const TTL_NORMAL = parseInt(process.env.CACHE_TTL_SECS      || "900");  // 15 min
const TTL_HIGH   = parseInt(process.env.CACHE_TTL_HIGH_SECS || "300");  // 5 min for threats

function getTTL(riskLevel) {
  return (riskLevel === "CRITICAL" || riskLevel === "HIGH") ? TTL_HIGH : TTL_NORMAL;
}

// ── Redis cache 

async function getFromRedis(ip) {
  const redis = getRedis();
  if (!redis) return null;
  try {
    const raw = await redis.get(`score:${ip}`);
    if (!raw) return null;
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

async function setInRedis(ip, data, ttlSecs) {
  const redis = getRedis();
  if (!redis) return;
  try {
    await redis.setex(`score:${ip}`, ttlSecs, JSON.stringify(data));
  } catch (_) {}
}

async function deleteFromRedis(ip) {
  const redis = getRedis();
  if (!redis) return;
  try { await redis.del(`score:${ip}`); } catch (_) {}
}

// ── Postgres cache 

async function getFromDB(ip) {
  try {
    const res = await db.query(
      `UPDATE score_cache
       SET hit_count = hit_count + 1
       WHERE ip = $1 AND expires_at > NOW()
       RETURNING payload, score, risk_level`,
      [ip]
    );
    if (!res.rows.length) return null;
    return res.rows[0].payload;
  } catch {
    return null;
  }
}

async function setInDB(ip, score, riskLevel, payload, ttlSecs) {
  try {
    await db.query(
      `INSERT INTO score_cache (ip, score, risk_level, payload, cached_at, expires_at)
       VALUES ($1, $2, $3, $4, NOW(), NOW() + ($5 || ' seconds')::INTERVAL)
       ON CONFLICT (ip) DO UPDATE SET
         score      = EXCLUDED.score,
         risk_level = EXCLUDED.risk_level,
         payload    = EXCLUDED.payload,
         cached_at  = NOW(),
         expires_at = NOW() + ($5 || ' seconds')::INTERVAL,
         hit_count  = score_cache.hit_count + 1`,
      [ip, score, riskLevel, JSON.stringify(payload), ttlSecs]
    );
  } catch (_) {}
}

// ── Public API

/**
 * Get a cached score result for an IP.
 * Checks Redis first, falls back to Postgres.
 * Returns null if not cached or expired.
 */
async function getCached(ip) {
  // 1. Redis
  const redisHit = await getFromRedis(ip);
  if (redisHit) return redisHit;

  // 2. Postgres fallback
  const dbHit = await getFromDB(ip);
  if (dbHit) {
    // Warm Redis back up
    const ttl = getTTL(dbHit.riskLevel);
    await setInRedis(ip, dbHit, ttl);
    return dbHit;
  }

  return null;
}

/**
 * Store a score result in both caches.
 */
async function setCached(ip, result) {
  const ttl = getTTL(result.riskLevel);
  const payload = { ...result, meta: { ...result.meta, cached: true, cachedAt: new Date().toISOString() } };

  await Promise.all([
    setInRedis(ip, payload, ttl),
    setInDB(ip, result.score, result.riskLevel, payload, ttl),
  ]);
}

/**
 * Invalidate cache for an IP (e.g. when it's blacklisted).
 */
async function invalidate(ip) {
  await Promise.all([
    deleteFromRedis(ip),
    db.query(`DELETE FROM score_cache WHERE ip = $1`, [ip]).catch(() => {}),
  ]);
}

/**
 * Cache stats for the admin dashboard.
 */
async function getCacheStats() {
  try {
    const redis  = getRedis();
    const dbRes  = await db.query(
      `SELECT COUNT(*) AS total,
              COUNT(*) FILTER (WHERE expires_at > NOW()) AS active,
              SUM(hit_count) AS total_hits,
              AVG(hit_count)::NUMERIC(10,1) AS avg_hits
       FROM score_cache`
    );
    const r = dbRes.rows[0];

    let redisKeys = 0;
    if (redis) {
      try { redisKeys = await redis.dbsize(); } catch (_) {}
    }

    return {
      redisKeys,
      dbTotal:    parseInt(r.total,      10) || 0,
      dbActive:   parseInt(r.active,     10) || 0,
      totalHits:  parseInt(r.total_hits, 10) || 0,
      avgHits:    parseFloat(r.avg_hits) || 0,
      ttlNormal:  TTL_NORMAL,
      ttlHigh:    TTL_HIGH,
    };
  } catch {
    return { redisKeys: 0, dbTotal: 0, dbActive: 0, totalHits: 0, avgHits: 0 };
  }
}

/**
 * Purge expired entries from Postgres (run nightly).
 */
async function purgeExpired() {
  try {
    const res = await db.query(`DELETE FROM score_cache WHERE expires_at <= NOW()`);
    return res.rowCount;
  } catch { return 0; }
}

module.exports = { getCached, setCached, invalidate, getCacheStats, purgeExpired };