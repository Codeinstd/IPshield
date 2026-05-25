
const db = require("./db");

// ── In-memory ring buffer (last 10k requests) 
const RING_SIZE = 10000;
const ring      = new Array(RING_SIZE);
let   ringHead  = 0;
let   ringCount = 0;

// ── Aggregated counters (reset on restart unless DB available) 
const counters = {
  totalRequests:  0,
  totalErrors:    0,
  totalBytes:     0,
  byEndpoint:     {},   // { "GET /score/:ip": { count, errors, totalMs, p50, p95, p99, statuses:{} } }
  byStatus:       {},   // { "200": 142, "404": 3 }
  byConsumer:     {},   // { "apiKey": { count, errors, lastSeen } }
  byHour:         {},   // { "2026-05-21T14": count }
  startedAt:      Date.now()
};

// ── Bootstrap DB table 
function bootstrap() {
  if (!db.isAvailable()) return;
  try {
    db.getDb().exec(`
      CREATE TABLE IF NOT EXISTS telemetry_requests (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        ts          INTEGER NOT NULL,
        method      TEXT NOT NULL,
        path        TEXT NOT NULL,
        route       TEXT,
        status      INTEGER NOT NULL,
        duration_ms INTEGER NOT NULL,
        req_bytes   INTEGER DEFAULT 0,
        res_bytes   INTEGER DEFAULT 0,
        api_key     TEXT,
        api_version TEXT,
        ip          TEXT,
        error       TEXT
      );
      CREATE INDEX IF NOT EXISTS idx_tel_ts    ON telemetry_requests(ts);
      CREATE INDEX IF NOT EXISTS idx_tel_route ON telemetry_requests(route);
      CREATE INDEX IF NOT EXISTS idx_tel_key   ON telemetry_requests(api_key);
    `);
    console.log("✓ Telemetry table ready");
  } catch (err) {
    console.error("Telemetry bootstrap error:", err.message);
  }
}

// ── Record one request 
function record({ method, path, route, status, durationMs, reqBytes = 0, resBytes = 0, apiKey, apiVersion, clientIp, error }) {
  const ts   = Date.now();
  const key  = `${method} ${route || path}`;
  const hour = new Date(ts).toISOString().slice(0, 13); // "2026-05-21T14"
  const isErr = status >= 400;

  // ── Update in-memory counters 
  counters.totalRequests++;
  if (isErr)  counters.totalErrors++;
  counters.totalBytes += resBytes;

  // By status
  const sc = String(status);
  counters.byStatus[sc] = (counters.byStatus[sc] || 0) + 1;

  // By hour
  counters.byHour[hour] = (counters.byHour[hour] || 0) + 1;

  // By endpoint
  if (!counters.byEndpoint[key]) {
    counters.byEndpoint[key] = {
      count: 0, errors: 0, totalMs: 0, minMs: Infinity, maxMs: 0,
      statuses: {}, latencies: []
    };
  }
  const ep = counters.byEndpoint[key];
  ep.count++;
  ep.totalMs += durationMs;
  ep.minMs    = Math.min(ep.minMs, durationMs);
  ep.maxMs    = Math.max(ep.maxMs, durationMs);
  ep.statuses[sc] = (ep.statuses[sc] || 0) + 1;
  if (isErr) ep.errors++;
  // Keep last 1000 latencies for percentile calc
  ep.latencies.push(durationMs);
  if (ep.latencies.length > 1000) ep.latencies.shift();

  // By consumer (hash the key for privacy)
  if (apiKey) {
    const masked = apiKey.slice(0, 8) + "••••";
    if (!counters.byConsumer[masked]) {
      counters.byConsumer[masked] = { count: 0, errors: 0, lastSeen: 0, firstSeen: ts };
    }
    const c = counters.byConsumer[masked];
    c.count++;
    if (isErr) c.errors++;
    c.lastSeen = ts;
  }

  // ── Ring buffer 
  ring[ringHead] = { ts, method, path, route, status, durationMs, apiVersion, clientIp, error: error || null };
  ringHead = (ringHead + 1) % RING_SIZE;
  if (ringCount < RING_SIZE) ringCount++;

  // ── Persist to SQLite (async, non-blocking) 
  if (db.isAvailable()) {
    try {
      await db.query(`
        INSERT INTO telemetry_requests
          (ts, method, path, route, status, duration_ms, req_bytes, res_bytes, api_key, api_version, ip, error)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `, [ts, method, path, route || path, status, durationMs, reqBytes, resBytes,
             apiKey ? apiKey.slice(0, 16) : null, apiVersion || null,
             clientIp || null, error || null]);
    } catch (_) {} // Never let telemetry break the app
  }
}

// ── Compute percentile from sorted array 
function percentile(arr, p) {
  if (!arr.length) return 0;
  const sorted = [...arr].sort((a, b) => a - b);
  const idx    = Math.floor((p / 100) * (sorted.length - 1));
  return sorted[idx];
}

// ── Get summary stats 
function getSummary() {
  const uptimeSecs = Math.floor((Date.now() - counters.startedAt) / 1000);
  const rps        = uptimeSecs > 0 ? (counters.totalRequests / uptimeSecs).toFixed(3) : 0;
  const errorRate  = counters.totalRequests > 0
    ? ((counters.totalErrors / counters.totalRequests) * 100).toFixed(2)
    : "0.00";

  // Top endpoints
  const topEndpoints = Object.entries(counters.byEndpoint)
    .map(([route, ep]) => ({
      route,
      count:       ep.count,
      errors:      ep.errors,
      errorRate:   ep.count > 0 ? ((ep.errors / ep.count) * 100).toFixed(1) + "%" : "0%",
      avgMs:       ep.count > 0 ? Math.round(ep.totalMs / ep.count) : 0,
      minMs:       ep.minMs === Infinity ? 0 : ep.minMs,
      maxMs:       ep.maxMs,
      p50:         percentile(ep.latencies, 50),
      p95:         percentile(ep.latencies, 95),
      p99:         percentile(ep.latencies, 99),
      statuses:    ep.statuses
    }))
    .sort((a, b) => b.count - a.count);

  // Hourly traffic (last 24h)
  const hourlyTraffic = Object.entries(counters.byHour)
    .sort(([a], [b]) => a.localeCompare(b))
    .slice(-24)
    .map(([hour, count]) => ({ hour, count }));

  // Top consumers
  const topConsumers = Object.entries(counters.byConsumer)
    .map(([key, c]) => ({
      key,
      count:     c.count,
      errors:    c.errors,
      errorRate: c.count > 0 ? ((c.errors / c.count) * 100).toFixed(1) + "%" : "0%",
      lastSeen:  new Date(c.lastSeen).toISOString(),
      firstSeen: new Date(c.firstSeen).toISOString()
    }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 20);

  return {
    uptime: {
      seconds: uptimeSecs,
      human:   formatUptime(uptimeSecs),
      startedAt: new Date(counters.startedAt).toISOString()
    },
    requests: {
      total:     counters.totalRequests,
      errors:    counters.totalErrors,
      errorRate: errorRate + "%",
      rps:       parseFloat(rps)
    },
    byStatus:      counters.byStatus,
    topEndpoints,
    hourlyTraffic,
    topConsumers
  };
}

// ── Get recent requests from ring buffer
function getRecentRequests(limit = 50) {
  const result = [];
  const start  = ringCount < RING_SIZE ? 0 : ringHead;
  for (let i = 0; i < Math.min(ringCount, limit); i++) {
    const idx = (start + ringCount - 1 - i) % RING_SIZE;
    if (ring[idx]) result.push(ring[idx]);
  }
  return result;
}

// ── DB-backed query for deeper history 
function getHistory({ route, status, limit = 100, from, to } = {}) {
  if (!db.isAvailable()) return getRecentRequests(limit);
  try {
    const conds  = [];
    const params = [];
    if (route)  { conds.push("route = ?");   params.push(route); }
    if (status) { conds.push("status = ?");  params.push(Number(status)); }
    if (from)   { conds.push("ts >= ?");     params.push(Number(from)); }
    if (to)     { conds.push("ts <= ?");     params.push(Number(to)); }
    const where = conds.length ? `WHERE ${conds.join(" AND ")}` : "";
    return await db.query(
      `SELECT * FROM telemetry_requests ${where} ORDER BY ts DESC LIMIT ?`
    ).all(...params, limit);
  } catch { return []; }
}

function formatUptime(secs) {
  const d = Math.floor(secs / 86400);
  const h = Math.floor((secs % 86400) / 3600);
  const m = Math.floor((secs % 3600) / 60);
  const s = secs % 60;
  if (d > 0) return `${d}d ${h}h ${m}m`;
  if (h > 0) return `${h}h ${m}m ${s}s`;
  if (m > 0) return `${m}m ${s}s`;
  return `${s}s`;
}

try { bootstrap(); } catch (_) {}

module.exports = { record, getSummary, getRecentRequests, getHistory };