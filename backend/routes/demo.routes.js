const express = require('express');
const router = express.Router();
const rateLimit = require('express-rate-limit');

const demoLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 20,             // 20 lookups/min per IP — generous for a demo card, tight enough to deter scraping
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests, please slow down.' },
});

const redis = require('../config/redis');

const CACHE_TTL_SECONDS = 60 * 60 * 24; // 24h — geo/ASN data doesn't change often
const CACHE_PREFIX = 'demo:geo:';

// Basic IPv4/IPv6 shape check — mirrors the frontend's looksLikeIp, defense in depth
function isValidIp(ip) {
  const v4 = /^(\d{1,3}\.){3}\d{1,3}$/;
  const v6 = /^[0-9a-fA-F:]+$/;
  if (v4.test(ip)) return ip.split('.').every(o => Number(o) <= 255);
  return v6.test(ip) && ip.includes(':');
}

router.get('/geo/:ip', demoLimiter, async (req, res) => {
  const { ip } = req.params;
  if (!isValidIp(ip)) {
    return res.status(400).json({ error: 'Invalid IP address' });
  }

  const cacheKey = CACHE_PREFIX + ip;
  let cached = null;

  try {
    if (redis && typeof redis.get === 'function') {
      cached = await redis.get(cacheKey);
    }
  } catch (err) {
    console.error('[demo/geo] Redis read failed:', err.message);
  }

  if (cached) {
    return res.json(JSON.parse(cached));
  }

  try {
    const upstream = await fetch(`https://ipwho.is/${encodeURIComponent(ip)}`);
    const data = await upstream.json();
    if (!data || data.success === false) throw new Error(data?.message || 'Upstream lookup failed');

    const result = {
      country: data.country || null,
      flagEmoji: data.flag?.emoji || null,
      provider: data.connection?.isp || data.connection?.org || null,
    };

    if (redis && typeof redis.set === 'function') {
      redis.set(cacheKey, JSON.stringify(result), 'EX', CACHE_TTL_SECONDS)
        .catch(err => console.error('[demo/geo] Redis write failed:', err.message));
    }

    res.json(result);
  } catch (err) {
    console.error('[demo/geo] Lookup failed for', ip, err.message);
    res.status(502).json({ error: 'Lookup failed' });
  }
});

module.exports = router;