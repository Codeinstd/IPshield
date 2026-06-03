require("dotenv").config();

const express    = require("express");
const cors       = require("cors");
const helmet     = require("helmet");
const morgan     = require("morgan");
const compression = require("compression");
const path       = require("path");
const rateLimit  = require("express-rate-limit");

// ── Route imports 
const scoreRoutes        = require("./routes/score.routes");
const statsRoutes        = require("./routes/stats.routes");
const auditRoutes        = require("./routes/audit.routes");
const streamRoutes       = require("./routes/stream.routes");
const watchlistRoutes    = require("./routes/watchlist.routes");
const whoisRoutes        = require("./routes/whois.routes");
const siemRoutes         = require("./routes/siem.routes");
const docsRoutes         = require("./routes/docs.routes");
const authMiddleware     = require("./middleware/auth.middleware");
const errorMiddleware    = require("./middleware/error.middleware");
const logger             = require("./utils/logger");
const reportRoutes       = require("./routes/report.routes");
const timelineRoutes     = require("./routes/timeline.routes");
const telemetryMiddleware = require("./middleware/telemetry.middleware");
const telemetryRoutes    = require("./routes/telemetry.routes");
const batchAsyncRoutes   = require("./routes/batchAsync.routes");
const threatRoutes       = require("./routes/threat.routes");
const cidrRoutes         = require("./routes/cidr.routes");
const siemTargetsRoutes  = require("./routes/siemTargets.routes");
const caseAccountsRoutes = require("./routes/caseAccounts.routes");
const clusterRoutes      = require("./routes/clusters.routes");
const keysRoutes         = require("./routes/keys.routes");
const authRoutes         = require("./routes/auth.routes");

// ── v2-only route imports 
const blacklistRoutes = require("./routes/blacklist.routes");
const casesRoutes     = require("./routes/cases.routes");

// ── App init 
const isProd = process.env.NODE_ENV === "production";
const app    = express();

// ── Request logger (dev only) 
app.use((req, res, next) => {
  console.log("REQ:", req.originalUrl);
  next();
});

// Serve landing page at /landing or make it the public homepage
app.get("/landing", (req, res) => {
  res.sendFile(path.join(__dirname, "../public", "landing.html"));
});

// Serve activate page
app.get("/activate", (req, res) => {
  res.sendFile(path.join(__dirname, "../public", "activate.html"));
});


// 1. SENTRY (must be first handler)
if (process.env.SENTRY_DSN) {
  try {
    const Sentry = require("@sentry/node");
    Sentry.init({ dsn: process.env.SENTRY_DSN, environment: process.env.NODE_ENV || "development" });
    app.use(Sentry.Handlers.requestHandler());
  } catch (_) {}
}

// 2. SECURITY HEADERS
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc:    ["'self'"],
      scriptSrc:     ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com", "https://cdn.jsdelivr.net", "https://www.googletagmanager.com", "https://www.google-analytics.com"],
      scriptSrcAttr: ["'unsafe-inline'"],
      styleSrc:      ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com", "https://cdnjs.cloudflare.com"],
      fontSrc:       ["'self'", "https://fonts.gstatic.com"],
      imgSrc:        ["'self'", "data:", "https://www.google-analytics.com", "https://*.basemaps.cartocdn.com", "https://*.cartocdn.com", "https://*.tile.openstreetmap.org", "https://*.openstreetmap.org"],
      connectSrc:    ["'self'", "https://api.ipify.org", "https://www.google-analytics.com", "https://region1.google-analytics.com"],
      workerSrc:     ["'self'", "blob:"],
      objectSrc:     ["'none'"],
    },
  },
  hsts: isProd ? { maxAge: 31536000, includeSubDomains: true } : false,
}));


// 3. CORS
const allowedOrigins = (process.env.ALLOWED_ORIGIN || "")
  .split(",").map(s => s.trim()).filter(Boolean);

app.use(cors({
  origin: (origin, cb) => {
    if (!origin || !allowedOrigins.length || allowedOrigins.includes(origin))
      return cb(null, true);
    cb(new Error(`CORS: origin ${origin} not allowed`));
  },
  methods:        ["GET", "POST", "PUT", "DELETE"],
  allowedHeaders: ["Content-Type", "x-api-key", "Authorization"],
}));


// 4. BODY PARSING & COMPRESSION
app.use(compression());
app.use(express.json({ limit: "50kb" }));
app.use(express.urlencoded({ extended: false }));


// 5. HTTP LOGGING
if (isProd) {
  app.use(morgan("combined", {
    stream: { write: msg => logger.info(msg.trim()) },
    skip:   req => req.path === "/api/health",
  }));
} else {
  app.use(morgan("dev"));
}


// 6. RATE LIMITING
const makeRateLimiter = (windowMs, max, message) => rateLimit({
  windowMs, max,
  standardHeaders: true,
  legacyHeaders:   false,
  handler: (req, res) => {
    const retryAfter = Math.ceil(windowMs / 1000);
    res.setHeader("Retry-After", retryAfter);
    res.status(429).json({ error: "rate_limit_exceeded", message, retryAfter, retryAfterMs: windowMs, limit: max, windowMs });
  },
});

["/api/", "/api/v1/", "/api/v2/"].forEach(prefix => {
  app.use(prefix, makeRateLimiter(15 * 60 * 1000, 200, "Too many requests. Try again in 15 minutes."));
});
["/api/score", "/api/v1/score", "/api/v2/score"].forEach(p => {
  app.use(p, makeRateLimiter(60 * 1000, 30, "Score rate limit: 30 requests per minute."));
});
["/api/whois", "/api/v1/whois", "/api/v2/whois"].forEach(p => {
  app.use(p, makeRateLimiter(60 * 1000, 20, "WHOIS rate limit: 20 requests per minute."));
});


// 7. TELEMETRY MIDDLEWARE (all /api/* requests)
app.use("/api", telemetryMiddleware);


// 8. STATIC FILES
app.use(express.static(path.join(__dirname, "../public"), {
  maxAge: isProd ? "1d" : 0,
  etag:   true,
}));


// 9. HTML PAGE ROUTES (public — no auth)
// Must come after static but before API routes and the catch-all.
app.get("/login", (req, res) => {
  res.sendFile(path.join(__dirname, "../public", "login.html"));
});

app.get("/activate", (req, res) => {
  const token = req.query.token || "";
  res.send(`<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Activate — IPShield</title>
  <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Syne:wght@700;800&display=swap" rel="stylesheet">
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { background: #080c0f; color: #c9d8e8; font-family: 'JetBrains Mono', monospace; min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 24px; }
    .card { background: #0d1117; border: 1px solid #1e2d3d; border-radius: 12px; width: 100%; max-width: 480px; padding: 40px; }
    .logo { font-family: 'Syne', sans-serif; font-size: 24px; font-weight: 800; margin-bottom: 28px; }
    .logo span { color: #00d9ff; }
    h2 { font-size: 18px; font-weight: 700; margin-bottom: 8px; }
    p  { font-size: 12px; color: #8fa8bc; line-height: 1.7; margin-bottom: 20px; }
    .meta { background: #111820; border-radius: 8px; padding: 14px 16px; margin-bottom: 24px; }
    .meta div { display: flex; justify-content: space-between; padding: 5px 0; border-bottom: 1px solid #1e2d3d; font-size: 11px; }
    .meta div:last-child { border-bottom: none; }
    .meta .lbl { color: #4a6278; }
    .meta .val { color: #c9d8e8; font-weight: 600; }
    .btn { width: 100%; padding: 14px; background: #00d9ff; color: #000; border: none; border-radius: 8px; font-size: 13px; font-weight: 700; cursor: pointer; font-family: inherit; letter-spacing: 0.5px; }
    .btn:disabled { opacity: 0.5; cursor: not-allowed; }
    .key-box { background: #111820; border: 1px solid #00d9ff; border-radius: 8px; padding: 16px; margin-bottom: 20px; word-break: break-all; font-size: 12px; color: #00d9ff; line-height: 1.6; }
    .copy-btn { width: 100%; padding: 10px; background: transparent; color: #00d9ff; border: 1px solid #00d9ff; border-radius: 8px; font-size: 12px; cursor: pointer; font-family: inherit; margin-top: 8px; }
    .error { color: #ff3355; font-size: 12px; margin-top: 12px; padding: 10px 14px; background: rgba(255,51,85,0.08); border-radius: 6px; border: 1px solid rgba(255,51,85,0.2); }
    .success-icon { font-size: 40px; text-align: center; margin-bottom: 16px; }
  </style>
</head>
<body>
<div class="card" id="card">
  <div class="logo">IP<span>Shield</span></div>
  <div id="content">
    <div style="text-align:center;color:#4a6278;font-size:12px;">Checking invite…</div>
  </div>
</div>
<script>
  const token = "${token}";
  async function init() {
    if (!token) { showError("No invite token found in the link."); return; }
    try {
      const res  = await fetch("/api/keys/activate/" + token);
      const data = await res.json();
      if (!data.valid) { showError("This invite link is invalid or has already been used."); return; }
      showInvite(data.invite);
    } catch (e) { showError("Failed to load invite details."); }
  }
  function showInvite(invite) {
    document.getElementById("content").innerHTML = \`
      <h2>You're invited</h2>
      <p>Click below to activate your IPShield API key. Save it somewhere safe — it will only be shown once.</p>
      <div class="meta">
        <div><span class="lbl">Name</span>        <span class="val">\${invite.name}</span></div>
        <div><span class="lbl">Role</span>        <span class="val">\${invite.role}</span></div>
        <div><span class="lbl">Daily limit</span> <span class="val">\${invite.daily_limit.toLocaleString()} requests</span></div>
      </div>
      <button class="btn" onclick="activate()">Activate My Key →</button>
      <div id="err"></div>\`;
  }
  async function activate() {
    const btn = document.querySelector(".btn");
    btn.disabled = true; btn.textContent = "Activating…";
    try {
      const res  = await fetch("/api/keys/activate/" + token, { method: "POST" });
      const data = await res.json();
      if (!res.ok) { showError(data.error || "Activation failed."); btn.disabled = false; btn.textContent = "Activate My Key →"; return; }
      showKey(data);
    } catch (e) { showError("Activation failed. Please try again."); btn.disabled = false; btn.textContent = "Activate My Key →"; }
  }
  function showKey(data) {
    document.getElementById("content").innerHTML = \`
      <div class="success-icon">✓</div>
      <h2 style="text-align:center;margin-bottom:8px;">Key activated</h2>
      <p style="text-align:center;">Save this key now — it will <strong style="color:#c9d8e8;">never be shown again</strong>.</p>
      <div class="key-box" id="keyVal">\${data.key}</div>
      <button class="copy-btn" onclick="copyKey()">Copy API Key</button>
      <div class="meta" style="margin-top:16px;">
        <div><span class="lbl">Name</span>  <span class="val">\${data.name}</span></div>
        <div><span class="lbl">Role</span>  <span class="val">\${data.role}</span></div>
        <div><span class="lbl">Limit</span> <span class="val">\${data.daily_limit.toLocaleString()} req/day</span></div>
      </div>
      <p style="margin-top:16px;font-size:11px;color:#4a6278;">
        Include your key in every API request:<br>
        <span style="color:#00d9ff;">x-api-key: \${data.key.slice(0,16)}••••</span>
      </p>\`;
  }
  function copyKey() {
    const key = document.getElementById("keyVal")?.textContent;
    if (!key) return;
    navigator.clipboard.writeText(key).then(() => {
      const btn = document.querySelector(".copy-btn");
      btn.textContent = "✓ Copied!";
      setTimeout(() => { btn.textContent = "Copy API Key"; }, 2000);
    });
  }
  function showError(msg) {
    document.getElementById("content").innerHTML =
      \`<div class="error">⚠ \${msg}</div>
       <p style="margin-top:16px;font-size:11px;color:#4a6278;">Contact the admin if you believe this is an error.</p>\`;
  }
  init();
</script>
</body>
</html>`);
});


// 10. PUBLIC API ROUTES (no auth required)

// Health
async function healthHandler(req, res) {
  const db                = require("./store/db");
  const monitor           = require("./jobs/monitor.job");
  const { getSIEMStatus } = require("./services/siem.service");
  const telemetry         = require("./store/telemetry.store");
  const tel               = telemetry.getSummary();
  const version           = req.baseUrl?.includes("/v1") ? "v1" : "v2";

  res.json({
    status:      "ok",
    version:     process.env.npm_package_version || "2.2.0",
    api_version: version,
    environment: process.env.NODE_ENV || "development",
    uptime:      Math.floor(process.uptime()),
    db:          await db.isHealthy() ? "connected" : "memory-only",
    monitor:     monitor.getMonitorStatus?.() || {},
    siem:        getSIEMStatus(),
    memoryMB:    Math.round(process.memoryUsage().heapUsed / 1024 / 1024),
    timestamp:   new Date().toISOString(),
    telemetry: {
      totalRequests: tel.requests.total,
      errorRate:     tel.requests.errorRate,
      rps:           tel.requests.rps,
      uptime:        tel.uptime.human,
      topEndpoints:  tel.topEndpoints.slice(0, 5).map(e => ({
        route: e.route, count: e.count, avgMs: e.avgMs, errorRate: e.errorRate,
      })),
    },
  });
}

app.get("/api/health",    healthHandler);
app.get("/api/v1/health", healthHandler);
app.get("/api/v2/health", healthHandler);

// Docs
app.use("/api/docs",    docsRoutes);
app.use("/api/v1/docs", require("./routes/docs.v1.routes"));
app.use("/api/v2/docs", require("./routes/docs.v2.routes"));

// Telemetry
app.use("/api/telemetry",    telemetryRoutes);
app.use("/api/v1/telemetry", telemetryRoutes);
app.use("/api/v2/telemetry", telemetryRoutes);

// Auth (login endpoint — issues JWTs, no key needed)
app.use("/api/v1/auth", authRoutes);
app.use("/api/v2/auth", authRoutes);
app.use("/api/auth",    authRoutes);

// Version info
function versionInfoHandler(req, res) {
  res.json({
    versions: {
      v1: { status: "stable", base_url: "/api/v1", docs: "/api/v1/docs", description: "Core IP intelligence — scoring, WHOIS, watchlist, audit, SIEM, reports", features: ["scoring","whois","watchlist","audit","siem","timeline","report"] },
      v2: { status: "latest", base_url: "/api/v2", docs: "/api/v2/docs", description: "Full platform — everything in v1 plus blacklist management and case management", features: ["scoring","whois","watchlist","audit","siem","timeline","report","blacklist","cases"] },
    },
    current: "v2",
    default: "/api routes to v2",
  });
}

app.get("/api/versions", versionInfoHandler);
app.get("/api/v1",       versionInfoHandler);
app.get("/api/v2",       versionInfoHandler);

// Key activation (public — no auth, must be before authMiddleware)
app.get("/api/keys/activate/:token",     keysRoutes);
app.post("/api/keys/activate/:token",    keysRoutes);
app.get("/api/v1/keys/activate/:token",  keysRoutes);
app.post("/api/v1/keys/activate/:token", keysRoutes);
app.get("/api/v2/keys/activate/:token",  keysRoutes);
app.post("/api/v2/keys/activate/:token", keysRoutes);


// 11. AUTH MIDDLEWARE (protects all /api/* routes below this point)

app.use("/api/", authMiddleware);

// Audit routes
app.use("/api/v1/audit", auditRoutes);
app.use("/api/v2/audit", auditRoutes);

// Stats routes
app.use("/api/v1/stats", statsRoutes);
app.use("/api/v2/stats", statsRoutes);


// 12. PROTECTED API ROUTES

// Helper — mount a router on multiple prefixes.
function mountShared(prefixes, routePath, routerArg) {
  prefixes.forEach(prefix => app.use(`${prefix}${routePath}`, routerArg));
}

const SHARED_PREFIXES = ["/api", "/api/v1", "/api/v2"];
const V2_PREFIXES     = ["/api", "/api/v2"];

// Shared (v1 + v2 + default /api)
mountShared(SHARED_PREFIXES, "/score",           scoreRoutes);
mountShared(SHARED_PREFIXES, "/score",           batchAsyncRoutes);
mountShared(SHARED_PREFIXES, "/stats",           statsRoutes);
mountShared(SHARED_PREFIXES, "/audit",           auditRoutes);
mountShared(SHARED_PREFIXES, "/watchlist",       watchlistRoutes);
mountShared(SHARED_PREFIXES, "/whois",           whoisRoutes);
mountShared(SHARED_PREFIXES, "/siem",            siemRoutes);
mountShared(SHARED_PREFIXES, "/siem",            siemTargetsRoutes);
mountShared(SHARED_PREFIXES, "/report",          reportRoutes);
mountShared(SHARED_PREFIXES, "/timeline",        timelineRoutes);
mountShared(SHARED_PREFIXES, "/threat",          threatRoutes);
mountShared(SHARED_PREFIXES, "/threat/clusters", clusterRoutes);
mountShared(SHARED_PREFIXES, "/keys",            keysRoutes);

// v2-only
mountShared(V2_PREFIXES, "/blacklist",      blacklistRoutes);
mountShared(V2_PREFIXES, "/blacklist/cidr", cidrRoutes);
mountShared(V2_PREFIXES, "/cases",          casesRoutes);
mountShared(V2_PREFIXES, "/cases",          caseAccountsRoutes);

// v1 stubs — explicit 404 for v2-only endpoints
app.use("/api/v1/blacklist", (req, res) => res.status(404).json({
  error: "not_available_in_v1", message: "Blacklist management is a v2 feature. Use /api/v2/blacklist", upgrade_url: "/api/v2/blacklist", docs: "/api/v2/docs",
}));

app.use("/api/v1/cases", (req, res) => res.status(404).json({
  error: "not_available_in_v1", message: "Case management is a v2 feature. Use /api/v2/cases", upgrade_url: "/api/v2/cases", docs: "/api/v2/docs",
}));


// 13. SPA FALLBACK & 404
app.use(express.static(path.join(__dirname, "../public")));

app.get(/.*/, (req, res, next) => {
  if (req.path.startsWith("/api")) return next();
  res.sendFile(path.join(__dirname, "../public/index.html"));
});

app.use((req, res) => res.status(404).json({
  error: "Not Found",
  path:  req.path,
  hint:  "See /api/versions for available API versions",
}));


// 14. ERROR HANDLERS (must be after all routes)

if (process.env.SENTRY_DSN) {
  try { app.use(require("@sentry/node").Handlers.errorHandler()); } catch (_) {}
}
app.use(errorMiddleware);


// 15. BACKGROUND JOBS
const { startMonitor } = require("./jobs/monitor.job");
startMonitor();

module.exports = app;