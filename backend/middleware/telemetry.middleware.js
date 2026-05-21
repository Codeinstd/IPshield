
const metrics = new Map();

function telemetryMiddleware(req, res, next) {
  const start = Date.now();

  res.on('finish', () => {
    const ms = Date.now() - start;
    const status = res.statusCode;
    const key = `${req.method}:${req.route?.path || req.path}`;

    const entry = metrics.get(key) || {
      hits: 0, errors: 0, totalMs: 0, minMs: Infinity, maxMs: 0, p95Samples: []
    };

    entry.hits++;
    entry.totalMs += ms;
    entry.minMs = Math.min(entry.minMs, ms);
    entry.maxMs = Math.max(entry.maxMs, ms);
    entry.p95Samples.push(ms);
    if (entry.p95Samples.length > 500) entry.p95Samples.shift();
    if (status >= 400) entry.errors++;

    metrics.set(key, entry);
  });

  next();
}

function getMetrics() {
  const result = {};
  for (const [key, m] of metrics.entries()) {
    const sorted = [...m.p95Samples].sort((a, b) => a - b);
    const p95idx = Math.floor(sorted.length * 0.95);
    result[key] = {
      hits: m.hits,
      errors: m.errors,
      errorRate: ((m.errors / m.hits) * 100).toFixed(1) + '%',
      avgMs: Math.round(m.totalMs / m.hits),
      minMs: m.minMs,
      maxMs: m.maxMs,
      p95Ms: sorted[p95idx] ?? null,
    };
  }
  return result;
}

module.exports = { telemetryMiddleware, getMetrics };