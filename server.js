const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');
const NodeCache = require('node-cache');
const path = require('path');
const { scoreIP, behaviorTracker } = require('./riskEngine');

const app = express();
const cache = new NodeCache({ stdTTL: 30, checkperiod: 10 }); // 30s TTL

// ── Middleware ────────────────────────────────────────────────
app.use(cors());
app.use(helmet({ contentSecurityPolicy: false }));
app.use(morgan('combined'));
app.use(express.json());
app.use(express.static(path.join(__dirname, '../public')));

// Rate limiting for the scoring endpoint itself
const limiter = rateLimit({
  windowMs: 60 * 1000,
  max: 200,
  standardHeaders: true,
  message: { error: 'Too many requests', retryAfter: 60 }
});
app.use('/api/', limiter);

// Request audit log (in-memory ring buffer, last 500)
const auditLog = [];
function logAudit(entry) {
  auditLog.unshift(entry);
  if (auditLog.length > 500) auditLog.pop();
}

// ── Helper: validate IP ───────────────────────────────────────
function isValidIP(ip) {
  const v4 = /^(\d{1,3}\.){3}\d{1,3}$/;
  const v6 = /^[0-9a-fA-F:]+$/;
  if (v4.test(ip)) {
    return ip.split('.').every(n => parseInt(n) <= 255);
  }
  return v6.test(ip) && ip.length <= 45;
}

// ── Routes ────────────────────────────────────────────────────

/**
 * GET /api/score/:ip
 * Score a single IP address
 */
app.get('/api/score/:ip', (req, res) => {
  const { ip } = req.params;
  const callerIP = req.headers['x-forwarded-for']?.split(',')[0] || req.socket.remoteAddress;

  if (!isValidIP(ip)) {
    return res.status(400).json({ error: 'Invalid IP address format' });
  }

  // Check cache
  const cacheKey = `score:${ip}`;
  const cached = cache.get(cacheKey);
  if (cached) {
    logAudit({ ip, callerIP, cached: true, score: cached.score, riskLevel: cached.riskLevel, ts: new Date().toISOString() });
    return res.json({ ...cached, meta: { ...cached.meta, cached: true } });
  }

  const result = scoreIP(ip, { callerIP });
  cache.set(cacheKey, result);
  logAudit({ ip, callerIP, cached: false, score: result.score, riskLevel: result.riskLevel, ts: new Date().toISOString() });

  res.json(result);
});

/**
 * POST /api/score/batch
 * Score up to 50 IPs at once
 */
app.post('/api/score/batch', (req, res) => {
  const { ips } = req.body;
  if (!Array.isArray(ips) || ips.length === 0) {
    return res.status(400).json({ error: '`ips` must be a non-empty array' });
  }
  if (ips.length > 50) {
    return res.status(400).json({ error: 'Maximum 50 IPs per batch request' });
  }

  const invalid = ips.filter(ip => !isValidIP(ip));
  if (invalid.length > 0) {
    return res.status(400).json({ error: 'Invalid IPs detected', invalid });
  }

  const results = ips.map(ip => {
    const cacheKey = `score:${ip}`;
    const cached = cache.get(cacheKey);
    if (cached) return { ...cached, meta: { ...cached.meta, cached: true } };
    const result = scoreIP(ip);
    cache.set(cacheKey, result);
    return result;
  });

  res.json({
    count: results.length,
    summary: {
      critical: results.filter(r => r.riskLevel === 'CRITICAL').length,
      high:     results.filter(r => r.riskLevel === 'HIGH').length,
      medium:   results.filter(r => r.riskLevel === 'MEDIUM').length,
      low:      results.filter(r => r.riskLevel === 'LOW').length,
    },
    results
  });
});

/**
 * GET /api/audit
 * Recent scoring audit log
 */
app.get('/api/audit', (req, res) => {
  const limit = Math.min(parseInt(req.query.limit) || 50, 200);
  res.json({ count: Math.min(limit, auditLog.length), entries: auditLog.slice(0, limit) });
});

/**
 * GET /api/stats
 * Runtime stats
 */
app.get('/api/stats', (req, res) => {
  const keys = cache.keys();
  const riskDist = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  keys.forEach(k => {
    const v = cache.get(k);
    if (v?.riskLevel) riskDist[v.riskLevel]++;
  });

  res.json({
    cachedScores: keys.length,
    trackedIPs: behaviorTracker.size,
    auditLogSize: auditLog.length,
    riskDistribution: riskDist,
    uptime: process.uptime(),
    memory: process.memoryUsage(),
    ts: new Date().toISOString()
  });
});

/**
 * GET /api/health
 */
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', ts: new Date().toISOString(), version: '1.0.0' });
});

// Catch-all → dashboard
app.get('/{*path}', (req, res) => {
  res.sendFile(path.join(__dirname, 'public/index.html'));
});

module.exports = app;

app.use(express.static(path.join(__dirname)));

app.use((req, res) => {
  res.sendFile(require('path').resolve(__dirname, 'public', 'index.html'));
});



