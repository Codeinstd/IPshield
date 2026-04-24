/**
 * app.js
 * Place in: backend/app.js
 */

const express      = require("express");
const cors         = require("cors");
const helmet       = require("helmet");
const morgan       = require("morgan");
const compression  = require("compression");
const path         = require("path");
const rateLimit    = require("express-rate-limit");

const scoreRoutes  = require("./routes/score.routes");
const statsRoutes  = require("./routes/stats.routes");
const auditRoutes  = require("./routes/audit.routes");
const streamRoutes = require("./routes/stream.routes");
const authMiddleware  = require("./middleware/auth.middleware");
const errorMiddleware = require("./middleware/error.middleware");
const logger       = require("./utils/logger");

const isProd = process.env.NODE_ENV === "production";
const app    = express();

// ── Sentry (if configured) ────────────────────────────────────────────────────
if (process.env.SENTRY_DSN) {
  try {
    const Sentry = require("@sentry/node");
    Sentry.init({ dsn: process.env.SENTRY_DSN, environment: process.env.NODE_ENV || "development" });
    app.use(Sentry.Handlers.requestHandler());
    logger.info("Sentry initialized");
  } catch (_) { logger.warn("Sentry package not installed — skipping"); }
}

// ── Security headers ──────────────────────────────────────────────────────────
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc:  ["'self'"],
      scriptSrc:   ["'self'"],
      styleSrc:    ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc:     ["'self'", "https://fonts.gstatic.com"],
      imgSrc:      ["'self'", "data:", "https://*.tile.openstreetmap.org", "https://*.basemaps.cartocdn.com", "https://*.openstreetmap.org"],
      connectSrc:  ["'self'"],
      workerSrc:   ["'self'", "blob:"],
      objectSrc:   ["'none'"],
      upgradeInsecureRequests: isProd ? [] : null
    }
  },
  hsts: isProd ? { maxAge: 31536000, includeSubDomains: true, preload: true } : false,
  referrerPolicy: { policy: "strict-origin-when-cross-origin" }
}));

// ── CORS ──────────────────────────────────────────────────────────────────────
const allowedOrigins = (process.env.ALLOWED_ORIGIN || "")
  .split(",").map(s => s.trim()).filter(Boolean);

app.use(cors({
  origin: (origin, cb) => {
    // Allow same-origin requests (no origin header) and configured origins
    if (!origin || !allowedOrigins.length || allowedOrigins.includes(origin)) return cb(null, true);
    cb(new Error(`CORS: origin ${origin} not allowed`));
  },
  methods:     ["GET", "POST"],
  allowedHeaders: ["Content-Type", "x-api-key"],
  credentials: false
}));

// ── Core middleware ───────────────────────────────────────────────────────────
app.use(compression());
app.use(express.json({ limit: "50kb" }));
app.use(express.urlencoded({ extended: false, limit: "50kb" }));

// Logging — structured in prod, dev-friendly locally
if (isProd) {
  app.use(morgan("combined", {
    stream: { write: msg => logger.info(msg.trim()) },
    skip:   (req) => req.path === "/api/health" // don't log health checks
  }));
} else {
  app.use(morgan("dev"));
}

// ── Rate limiting ─────────────────────────────────────────────────────────────
const globalLimiter = rateLimit({
  windowMs:         15 * 60 * 1000,
  max:              100,
  standardHeaders:  true,
  legacyHeaders:    false,
  message:          { error: "Too many requests", retryAfter: "15 minutes" }
});

const scoreLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute window
  max:      30,        // 30 score requests per minute
  standardHeaders: true,
  legacyHeaders:   false,
  message: { error: "Score rate limit exceeded", retryAfter: "1 minute" }
});

const batchLimiter = rateLimit({
  windowMs: 60 * 1000,
  max:      5, // 5 batch requests per minute
  message:  { error: "Batch rate limit exceeded", retryAfter: "1 minute" }
});

app.use("/api/", globalLimiter);
app.use("/api/score/:ip", scoreLimiter);
app.use("/api/score/batch", batchLimiter);

// ── Static files ──────────────────────────────────────────────────────────────
app.use(express.static(path.join(__dirname, "../public"), {
  maxAge: isProd ? "1d" : 0,
  etag:   true
}));

// ── Auth — protects all /api/* routes ─────────────────────────────────────────
app.use("/api/", authMiddleware);

// ── API routes ────────────────────────────────────────────────────────────────
app.use("/api/score",  scoreRoutes);
app.use("/api/stats",  statsRoutes);
app.use("/api/audit",  auditRoutes);
app.use("/api/stream", streamRoutes);

// ── Health check (no auth required) ──────────────────────────────────────────
app.get("/api/health", (req, res) => {
  const db = require("./store/db");
  res.json({
    status:      "ok",
    version:     process.env.npm_package_version || "1.0.0",
    environment: process.env.NODE_ENV || "development",
    uptime:      Math.floor(process.uptime()),
    db:          db.isAvailable() ? "connected" : "memory-only",
    memoryMB:    Math.round(process.memoryUsage().heapUsed / 1024 / 1024),
    timestamp:   new Date().toISOString()
  });
});

// ── SPA fallback ──────────────────────────────────────────────────────────────
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "../public/index.html"));
});

// ── 404 ───────────────────────────────────────────────────────────────────────
app.use((req, res) => {
  res.status(404).json({ error: "Not Found", path: req.path });
});

// ── Sentry error handler (must be before custom error handler) ────────────────
if (process.env.SENTRY_DSN) {
  try {
    const Sentry = require("@sentry/node");
    app.use(Sentry.Handlers.errorHandler());
  } catch (_) {}
}

// ── Global error handler ──────────────────────────────────────────────────────
app.use(errorMiddleware);

module.exports = app;