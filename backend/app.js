/**
 * app.js — backend
 * Place in: backend/app.js
 * Updated: adds SIEM route + rate limit feedback headers
 */

const express      = require("express");
const cors         = require("cors");
const helmet       = require("helmet");
const morgan       = require("morgan");
const compression  = require("compression");
const path         = require("path");
const rateLimit    = require("express-rate-limit");

const scoreRoutes     = require("./routes/score.routes");
const statsRoutes     = require("./routes/stats.routes");
const auditRoutes     = require("./routes/audit.routes");
const streamRoutes    = require("./routes/stream.routes");
const watchlistRoutes = require("./routes/watchlist.routes");
const whoisRoutes     = require("./routes/whois.routes");
const siemRoutes      = require("./routes/siem.routes");
const docsRoutes      = require("./routes/docs.routes");
const authMiddleware  = require("./middleware/auth.middleware");
const errorMiddleware = require("./middleware/error.middleware");
const logger          = require("./utils/logger");

const isProd = process.env.NODE_ENV === "production";
const app    = express();

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
      scriptSrc:  ["'self'", "https://cdnjs.cloudflare.com"],
      styleSrc:   ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com", "https://cdnjs.cloudflare.com"],
      fontSrc:    ["'self'", "https://fonts.gstatic.com"],
      imgSrc:     ["'self'", "data:", 
                    "https://*.basemaps.cartocdn.com", 
                    "https://*.cartocdn.com",
                    "https://*.tile.openstreetmap.org",  // ← add this
                    "https://*.openstreetmap.org"         // ← add this
                  ],
      connectSrc: ["'self'", "https://api.ipify.org"],
      workerSrc:  ["'self'", "blob:"],
      objectSrc:  ["'none'"]
    }
  },
  hsts: isProd ? { maxAge: 31536000, includeSubDomains: true } : false
}));

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
  windowMs,
  max,
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

app.use("/api/",      makeRateLimiter(15 * 60 * 1000, 200, "Too many requests. Try again in 15 minutes."));
app.use("/api/score", makeRateLimiter(60 * 1000,       30,  "Score rate limit: 30 requests per minute."));
app.use("/api/whois", makeRateLimiter(60 * 1000,       20,  "WHOIS rate limit: 20 requests per minute."));

// ── Static files  
app.use(express.static(path.join(__dirname, "../public"), { maxAge: isProd ? "1d" : 0, etag: true }));

// ── Docs (public — no auth)  
app.use("/api/docs", docsRoutes);

// ── Health check (public — no auth) 
app.get("/api/health", (req, res) => {
  const db      = require("./store/db");
  const monitor = require("./jobs/monitor.job");
  const { getSIEMStatus } = require("./services/siem.service");
  res.json({
    status:      "ok",
    version:     process.env.npm_package_version || "2.2.0",
    environment: process.env.NODE_ENV || "development",
    uptime:      Math.floor(process.uptime()),
    db:          db.isAvailable() ? "connected" : "memory-only",
    monitor:     monitor.getMonitorStatus(),
    siem:        getSIEMStatus(),
    memoryMB:    Math.round(process.memoryUsage().heapUsed / 1024 / 1024),
    timestamp:   new Date().toISOString()
  });
});

// ── Auth  
app.use("/api/", authMiddleware);

// ── API routes  
app.use("/api/score",     scoreRoutes);
app.use("/api/stats",     statsRoutes);
app.use("/api/audit",     auditRoutes);
app.use("/api/stream",    streamRoutes);
app.use("/api/watchlist", watchlistRoutes);
app.use("/api/whois",     whoisRoutes);
app.use("/api/siem",      siemRoutes);

// ── SPA fallback  
app.get("/", (req, res) => res.sendFile(path.join(__dirname, "../public/index.html")));
app.use((req, res) => res.status(404).json({ error: "Not Found", path: req.path }));

if (process.env.SENTRY_DSN) {
  try { app.use(require("@sentry/node").Handlers.errorHandler()); } catch (_) {}
}
app.use(errorMiddleware);

const { startMonitor } = require("./jobs/monitor.job");
startMonitor();

module.exports = app;