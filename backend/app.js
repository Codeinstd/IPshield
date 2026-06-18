const express    = require("express");
const cors       = require("cors");
const helmet     = require("helmet");
const morgan     = require("morgan");
const compression = require("compression");
const path       = require("path");
const rateLimit  = require("express-rate-limit");

// Route imports 
const scoreRoutes           = require("./routes/score.routes");
const statsRoutes           = require("./routes/stats.routes");
const auditRoutes           = require("./routes/audit.routes");
const streamRoutes          = require("./routes/stream.routes");
const watchlistRoutes       = require("./routes/watchlist.routes");
const whoisRoutes           = require("./routes/whois.routes");
const siemRoutes            = require("./routes/siem.routes");
const docsRoutes            = require("./routes/docs.routes");
const authMiddleware        = require("./middleware/auth.middleware");
const errorMiddleware       = require("./middleware/error.middleware");
const logger                = require("./utils/logger");
const reportRoutes          = require("./routes/report.routes");
const timelineRoutes        = require("./routes/timeline.routes");
const telemetryMiddleware   = require("./middleware/telemetry.middleware");
const telemetryRoutes       = require("./routes/telemetry.routes");
const batchAsyncRoutes      = require("./routes/batchAsync.routes");
const threatRoutes          = require("./routes/threat.routes");
const cidrRoutes            = require("./routes/cidr.routes");
const siemTargetsRoutes     = require("./routes/siemTargets.routes");
const caseAccountsRoutes    = require("./routes/caseAccounts.routes");
const clusterRoutes         = require("./routes/clusters.routes");
const keysRoutes            = require("./routes/keys.routes");
const authRoutes            = require("./routes/auth.routes");
const accessRequestRoutes   = require("./routes/accessRequest.routes");
const gdprRoutes            = require("./routes/gdpr.routes");
const mfaRoutes             = require("./routes/mfa.routes");
const scanRoutes            = require("./routes/scan.routes");
const {requireAuth}         = require("./middleware/auth");
const scan                  = require("./store/scan.store");
const vulnreportRoutes      = require("./routes/vulnreport.routes");


// v2-only route imports 
const blacklistRoutes = require("./routes/blacklist.routes");
const casesRoutes     = require("./routes/cases.routes");

// App init 
const isProd = process.env.NODE_ENV === "production";
const app    = express();

// Request logger 
app.use((req, res, next) => {
  console.log("REQ:", req.originalUrl);
  next();
});

// Sentry (must be first handler)
if (process.env.SENTRY_DSN) {
  try {
    const Sentry = require("@sentry/node");
    Sentry.init({ dsn: process.env.SENTRY_DSN, environment: process.env.NODE_ENV || "development" });
    app.use(Sentry.Handlers.requestHandler());
  } catch (_) {}
}

//  Security Headers
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],

        scriptSrc: [
          "'self'",
          "'unsafe-inline'",
          "https://cdnjs.cloudflare.com",
          "https://cdn.jsdelivr.net",
          "https://www.googletagmanager.com",
          "https://www.google-analytics.com",
          "https://consent.cookiebot.com",
          "https://consentcdn.cookiebot.com",
        ],

        scriptSrcAttr: ["'unsafe-inline'"],

        styleSrc: [
          "'self'",
          "'unsafe-inline'",
          "https://fonts.googleapis.com",
          "https://cdnjs.cloudflare.com",
        ],

        fontSrc: [
          "'self'",
          "https://fonts.gstatic.com",
        ],

        imgSrc: [
          "'self'",
          "data:",
          "https://www.google-analytics.com",
          "https://*.basemaps.cartocdn.com",
          "https://*.cartocdn.com",
          "https://*.tile.openstreetmap.org",
          "https://*.openstreetmap.org",
          "https://consent.cookiebot.com",
          "https://consentcdn.cookiebot.com",
        ],

        connectSrc: [
          "'self'",
          "https://api.ipify.org",
          "https://www.google-analytics.com",
          "https://region1.google-analytics.com",
          "https://consent.cookiebot.com",
          "https://consentcdn.cookiebot.com",
        ],

        frameSrc: [
          "'self'",
          "https://consent.cookiebot.com",
          "https://consentcdn.cookiebot.com",
        ],

        workerSrc: [
          "'self'",
          "blob:",
        ],

        objectSrc: ["'none'"],
      },
    },

    hsts: isProd
      ? {
          maxAge: 31536000,
          includeSubDomains: true,
        }
      : false,
  })
);

//  CORS
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

// Body parsing & compression
app.use(compression());
app.use(express.json({ limit: "50kb" }));
app.use(express.urlencoded({ extended: false }));


//  Http Logging
if (isProd) {
  app.use(morgan("combined", {
    stream: { write: msg => logger.info(msg.trim()) },
    skip:   req => req.path === "/api/health",
  }));
} else {
  app.use(morgan("dev"));
}

// Rate Limiting
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


// Telemetry Authmiddleware (all /api/* requests)
app.use("/api", telemetryMiddleware);


//  Static files
app.use(express.static(path.join(__dirname, "../public"), {
  maxAge: isProd ? "1d" : 0,
  etag:   true,
}));

// Serve activate page
app.get("/activate", (req, res) => {
  res.sendFile(path.join(__dirname, "../public", "activate.html"));
});

// PUBLIC API ROUTES (no auth required)

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

// MFA routes
app.use("/api/v1/mfa", mfaRoutes);
app.use("/api/v2/mfa", mfaRoutes);

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

// AccessRequest
app.use("/api/access-request", accessRequestRoutes);

//ViewReport
app.use("/api/v2/report", reportRoutes);

// GDPR Tooling
app.use("/api/v2/gdpr", gdprRoutes);

// scan 
app.use("/api/v2/scan", requireAuth, scanRoutes);

// vulnerability scan 
app.use("/api/v2/cases", vulnreportRoutes);


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

// Public — no auth, must be before authMiddleware
app.use("/api/keys",    keysRoutes);
app.use("/api/v1/keys", keysRoutes);
app.use("/api/v2/keys", keysRoutes);


//  Auth Middleware (protects all /api/* routes below this point)
app.use("/api/", (req, res, next) => {
  if (req.path.startsWith("/docs") ||
      req.path.startsWith("/telemetry/dashboard")) {
    return next();
  }
  return authMiddleware(req, res, next);
});

// Audit routes
app.use("/api/v1/audit", auditRoutes);
app.use("/api/v2/audit", auditRoutes);

// Stats routes
app.use("/api/v1/stats", statsRoutes);
app.use("/api/v2/stats", statsRoutes);


//  ProtectedD API Routes

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

// v2-only
mountShared(V2_PREFIXES, "/blacklist",           blacklistRoutes);
mountShared(V2_PREFIXES, "/blacklist/cidr",      cidrRoutes);
mountShared(V2_PREFIXES, "/cases",               casesRoutes);
mountShared(V2_PREFIXES, "/cases",               caseAccountsRoutes);

// v1 stubs — explicit 404 for v2-only endpoints
app.use("/api/v1/blacklist", (req, res) => res.status(404).json({
  error: "not_available_in_v1", message: "Blacklist management is a v2 feature. Use /api/v2/blacklist", upgrade_url: "/api/v2/blacklist", docs: "/api/v2/docs",
}));

app.use("/api/v1/cases", (req, res) => res.status(404).json({
  error: "not_available_in_v1", message: "Case management is a v2 feature. Use /api/v2/cases", upgrade_url: "/api/v2/cases", docs: "/api/v2/docs",
}));

//  SPA Fallback & 404
app.use(express.static(path.join(__dirname, "../public")));

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "../public", "index.html"));
});

// Serve landing page at /landing or make it the public homepage
app.get("/index", (req, res) => {
  res.sendFile(path.join(__dirname, "../public", "index.html"));
});

app.get("/dashboard", (req, res) => {
  res.sendFile(path.join(__dirname, "../public", "dashboard.html"));
});

// 9. HTML Page routes (public — no auth)
app.get("/login", (req, res) => {
  res.sendFile(path.join(__dirname, "../public", "login.html"));
});

// AFTER — only valid mfaSetup tokens get through
app.get("/mfa-setup", (req, res) => {
  const token = req.query.token || 
    (req.headers.authorization || "").replace("Bearer ", "");

  if (!token) {
    return res.redirect("/login");
  }

  try {
    const jwt     = require("jsonwebtoken");
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    // Must be a setup token, not a full session token
    if (!decoded.mfaSetup) {
      return res.redirect("/login");
    }

    res.sendFile(path.join(__dirname, "../public", "mfa-setup.html"));
  } catch {
    return res.redirect("/login");
  }
});

app.get("/forgot-password", (req, res) => {
  res.sendFile(path.join(__dirname, "../public", "forgot-password.html"));
});
 
app.get("/reset-password", (req, res) => {
  res.sendFile(path.join(__dirname, "../public", "reset-password.html"));
});

app.get(/.*/, (req, res) => {
  res.sendFile(path.join(__dirname, "../public", "index.html"));
});

app.use((req, res) => res.status(404).json({
  error: "Not Found",
  path:  req.path,
  hint:  "See /api/versions for available API versions",
}));

// Error Handlers (must be after all routes)
if (process.env.SENTRY_DSN) {
  try { app.use(require("@sentry/node").Handlers.errorHandler()); } catch (_) {}
}
app.use(errorMiddleware);

// Background Jobs
const { startMonitor } = require("./jobs/monitor.job");
startMonitor();

module.exports = app;