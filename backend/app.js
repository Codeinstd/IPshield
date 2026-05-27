
const express      = require("express");
const cors         = require("cors");
const helmet       = require("helmet");
const morgan       = require("morgan");
const compression  = require("compression");
const path         = require("path");
const rateLimit    = require("express-rate-limit");

// ── Routes
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

// v2-only Routes
const blacklistRoutes = require("./routes/blacklist.routes");
const casesRoutes     = require("./routes/cases.routes");


const isProd = process.env.NODE_ENV === "production";
const app    = express();


// ── Security & middleware 
if (process.env.SENTRY_DSN) {
  try {
    const Sentry = require("@sentry/node");
    Sentry.init({ dsn: process.env.SENTRY_DSN, environment: process.env.NODE_ENV || "development" });
    app.use(Sentry.Handlers.requestHandler());
  } catch (_) {}
}

app.use(helmet({
 contentSecurityPolicy: {
  directives: {
    defaultSrc: ["'self'"],

    scriptSrc: [
      "'self'",
      "'unsafe-inline'",
      "https://cdnjs.cloudflare.com",
      "https://cdn.jsdelivr.net",
      "https://www.googletagmanager.com",
      "https://www.google-analytics.com"
    ],

    scriptSrcAttr: ["'unsafe-inline'"],

    styleSrc: [
      "'self'",
      "'unsafe-inline'",
      "https://fonts.googleapis.com",
      "https://cdnjs.cloudflare.com"
    ],

    fontSrc: [
      "'self'",
      "https://fonts.gstatic.com"
    ],

    imgSrc: [
      "'self'",
      "data:",
      "https://www.google-analytics.com",
      "https://*.basemaps.cartocdn.com",
      "https://*.cartocdn.com",
      "https://*.tile.openstreetmap.org",
      "https://*.openstreetmap.org"
    ],

    connectSrc: [
      "'self'",
      "https://api.ipify.org",
      "https://www.google-analytics.com",
      "https://region1.google-analytics.com"
    ],

    workerSrc: [
      "'self'",
      "blob:"
    ],

    objectSrc: ["'none'"]
  }
},
  hsts: isProd ? { maxAge: 31536000, includeSubDomains: true } : false
}

));

const allowedOrigins = (process.env.ALLOWED_ORIGIN || "").split(",").map(s => s.trim()).filter(Boolean);
app.use(cors({
  origin: (origin, cb) => {
    if (!origin || !allowedOrigins.length || allowedOrigins.includes(origin)) return cb(null, true);
    cb(new Error(`CORS: origin ${origin} not allowed`));
  },
  methods:        ["GET", "POST", "DELETE"],
  allowedHeaders: ["Content-Type", "x-api-key"]
}));

app.use(compression());
app.use(express.json({ limit: "50kb" }));
app.use(express.urlencoded({ extended: false }));

if (isProd) {
  app.use(morgan("combined", { stream: { write: msg => logger.info(msg.trim()) }, skip: req => req.path === "/api/health" }));
} else {
  app.use(morgan("dev"));
}


// ── Rate limiting with structured error body 
const makeRateLimiter = (windowMs, max, message) => rateLimit({
  windowMs, max,
  standardHeaders: true,
  legacyHeaders:   false,
  handler: (req, res) => {
    const retryAfter = Math.ceil(windowMs / 1000);
    res.setHeader("Retry-After", retryAfter);
    res.status(429).json({
      error:        "rate_limit_exceeded",
      message,
      retryAfter,
      retryAfterMs: windowMs,
      limit:        max,
      windowMs
    });
  }
});


// Apply to all /api/* variants
["/api/", "/api/v1/", "/api/v2/"].forEach(prefix => {
  app.use(prefix, makeRateLimiter(15 * 60 * 1000, 200, "Too many requests. Try again in 15 minutes."));
});
["/api/score", "/api/v1/score", "/api/v2/score"].forEach(p => {
  app.use(p, makeRateLimiter(60 * 1000, 30, "Score rate limit: 30 requests per minute."));
});
["/api/whois", "/api/v1/whois", "/api/v2/whois"].forEach(p => {
  app.use(p, makeRateLimiter(60 * 1000, 20, "WHOIS rate limit: 20 requests per minute."));
});

// telemry checker
app.use("/api", telemetryMiddleware);

// ── Static files  
app.use(express.static(path.join(__dirname, "../public"), { maxAge: isProd ? "1d" : 0, etag: true }));


// ── Health (public — all versions)
async function healthHandler(req, res) {
  const db                  = require("./store/db");
  const monitor             = require("./jobs/monitor.job");
  const { getSIEMStatus }   = require("./services/siem.service");
  const telemetry           = require("./store/telemetry.store");   
  const tel                 = telemetry.getSummary();  

  const version = req.baseUrl?.includes("/v1") ? "v1" : "v2";
  // Detect which version is being called
  // const version = req.path.includes("/v1/") ? "v1"
  //                : req.path.includes("/v2/") ? "v2"
  //                : "v1"; // default
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
          route:    e.route,
          count:    e.count,
          avgMs:    e.avgMs,
          errorRate:e.errorRate
        }))
      }
  });
}
 
app.get("/api/health",    healthHandler);
app.get("/api/v1/health", healthHandler);
app.get("/api/v2/health", healthHandler);
 
// ── Docs (public — all versions) 
// Each version gets its own spec
app.use("/api/docs",    docsRoutes);
app.use("/api/v1/docs", require("./routes/docs.v1.routes"));
app.use("/api/v2/docs", require("./routes/docs.v2.routes"));

// Telemetry (internal)
app.use("/api/telemetry",    telemetryRoutes);
app.use("/api/v1/telemetry", telemetryRoutes);
app.use("/api/v2/telemetry", telemetryRoutes);




// ── Version info endpoints (public) 
function versionInfoHandler(req, res) {
  const isV1 = req.path.startsWith("/v1") || req.baseUrl?.includes("/v1");
  res.json({
    versions: {
      v1: {
        status:      "stable",
        base_url:    "/api/v1",
        docs:        "/api/v1/docs",
        description: "Core IP intelligence — scoring, WHOIS, watchlist, audit, SIEM, reports",
        features:    ["scoring","whois","watchlist","audit","siem","timeline","report"]
      },
      v2: {
        status:      "latest",
        base_url:    "/api/v2",
        docs:        "/api/v2/docs",
        description: "Full platform — everything in v1 plus blacklist management and case management",
        features:    ["scoring","whois","watchlist","audit","siem","timeline","report","blacklist","cases"]
      }
    },
    current:  "v2",
    default:  "/api routes to v2"
  });
}
 
app.get("/api/versions", versionInfoHandler);
app.get("/api/v1",       versionInfoHandler);
app.get("/api/v2",       versionInfoHandler);

// ── Auth middleware 
app.use("/api/",    authMiddleware);
app.use("/api/v1/", authMiddleware);
app.use("/api/v2/", authMiddleware);

// ── Helper: mount shared routes on multiple prefixes 
function mountShared(prefixes, path, router) {
  prefixes.forEach(prefix => app.use(`${prefix}${path}`, router));
}

// ── Shared routes (v1 + v2 + default) 
const SHARED_PREFIXES = ["/api", "/api/v1", "/api/v2"];
 
mountShared(SHARED_PREFIXES, "/score",     scoreRoutes);
mountShared(SHARED_PREFIXES, "/score", batchAsyncRoutes);
mountShared(SHARED_PREFIXES, "/stats",     statsRoutes);
mountShared(SHARED_PREFIXES, "/audit",     auditRoutes);
mountShared(SHARED_PREFIXES, "/watchlist", watchlistRoutes);
mountShared(SHARED_PREFIXES, "/whois",     whoisRoutes);
mountShared(SHARED_PREFIXES, "/siem",      siemRoutes);
mountShared(SHARED_PREFIXES, "/report",    reportRoutes);
mountShared(SHARED_PREFIXES, "/timeline",  timelineRoutes);
mountShared(SHARED_PREFIXES, "/threat", threatRoutes);

// ── v2-only routes 
const V2_PREFIXES = ["/api", "/api/v2"]; // /api defaults to v2
 
mountShared(V2_PREFIXES, "/blacklist", blacklistRoutes);
mountShared(V2_PREFIXES, "/cases",     casesRoutes);


// ── v1 — explicit 404 for v2-only features 
app.use("/api/v1/blacklist", (req, res) => {
  res.status(404).json({
    error:       "not_available_in_v1",
    message:     "Blacklist management is a v2 feature. Use /api/v2/blacklist",
    upgrade_url: "/api/v2/blacklist",
    docs:        "/api/v2/docs"
  });
});
 
app.use("/api/v1/cases", (req, res) => {
  res.status(404).json({
    error:       "not_available_in_v1",
    message:     "Case management is a v2 feature. Use /api/v2/cases",
    upgrade_url: "/api/v2/cases",
    docs:        "/api/v2/docs"
  });
});

// ── SPA fallback 
app.get("/", (req, res) => res.sendFile(path.join(__dirname, "../public/index.html")));
 
app.use((req, res) => res.status(404).json({
  error:   "Not Found",
  path:    req.path,
  hint:    "See /api/versions for available API versions"
}));

if (process.env.SENTRY_DSN) {
  try { app.use(require("@sentry/node").Handlers.errorHandler()); } catch (_) {}
}
app.use(errorMiddleware);

const { startMonitor } = require("./jobs/monitor.job");
startMonitor();

module.exports = app;