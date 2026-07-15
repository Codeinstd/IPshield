const express = require('express');
const router = express.Router();
const { getRedis } = require('../config/redis');

const CACHE_TTL_SECONDS = 60 * 60 * 24; // 24h
const CACHE_PREFIX = 'demo:geo:';

function isValidIp(ip) {
  const v4 = /^(\d{1,3}\.){3}\d{1,3}$/;
  const v6 = /^[0-9a-fA-F:]+$/;
  if (v4.test(ip)) return ip.split('.').every(o => Number(o) <= 255);
  return v6.test(ip) && ip.includes(':');
}

const rateLimit = require('express-rate-limit');
const demoLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests, please slow down.' },
});

router.get('/geo/:ip', demoLimiter, async (req, res) => {
  const { ip } = req.params;
  if (!isValidIp(ip)) {
    return res.status(400).json({ error: 'Invalid IP address' });
  }

  const cacheKey = CACHE_PREFIX + ip;
  const redis = getRedis(); // null if not connected — always check before use

  if (redis) {
    try {
      const cached = await redis.get(cacheKey);
      if (cached) return res.json(JSON.parse(cached));
    } catch (err) {
      console.error('[demo/geo] Redis read failed:', err.message);
    }
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

    if (redis) {
      redis.set(cacheKey, JSON.stringify(result), { EX: CACHE_TTL_SECONDS })
        .catch(err => console.error('[demo/geo] Redis write failed:', err.message));
    }

    res.json(result);
  } catch (err) {
    console.error('[demo/geo] Lookup failed for', ip, err.message);
    res.status(502).json({ error: 'Lookup failed' });
  }
});

module.exports = router;