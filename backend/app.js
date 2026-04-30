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
const authMiddleware  = require("./middleware/auth.middleware");
const errorMiddleware = require("./middleware/error.middleware");
const logger          = require("./utils/logger");
const docsRoutes      = require("./routes/docs.routes");

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
    scriptSrc: ["'self'", "https://cdnjs.cloudflare.com", "'sha256-HWYeuO854TnBqC+pc2O1r0NIztXJLBa+KcR5sh0k1EY='"],
    scriptSrcAttr: ["'none'"],
    styleSrc:  ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com", "https://cdnjs.cloudflare.com"],
    fontSrc:    ["'self'", "https://fonts.gstatic.com"],
    imgSrc:     ["'self'", "data:", "https://*.tile.openstreetmap.org", "https://*.basemaps.cartocdn.com"],
    connectSrc: ["'self'"],
    workerSrc:  ["'self'", "blob:"],
    objectSrc:  ["'none'"],
    connectSrc: ["'self'", "https://api.ipify.org"],
    
  }
},
  hsts: isProd ? { maxAge: 31536000, includeSubDomains: true } : false
}));

app.use("/api/docs", docsRoutes);

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

app.use("/api/",      rateLimit({ windowMs: 15 * 60 * 1000, max: 200, standardHeaders: true, legacyHeaders: false }));
app.use("/api/score", rateLimit({ windowMs: 60 * 1000, max: 30, standardHeaders: true, legacyHeaders: false }));
app.use("/api/whois", rateLimit({ windowMs: 60 * 1000, max: 20, standardHeaders: true, legacyHeaders: false }));

app.use(express.static(path.join(__dirname, "../public"), { maxAge: isProd ? "1d" : 0, etag: true }));

app.get("/api/health", (req, res) => {
  const db      = require("./store/db");
  const monitor = require("./jobs/monitor.job");
  res.json({
    status: "ok", version: process.env.npm_package_version || "2.0.0",
    environment: process.env.NODE_ENV || "development",
    uptime: Math.floor(process.uptime()),
    db: db.isAvailable() ? "connected" : "memory-only",
    monitor: monitor.getMonitorStatus(),
    memoryMB: Math.round(process.memoryUsage().heapUsed / 1024 / 1024),
    timestamp: new Date().toISOString()
  });
});

app.use("/api/", authMiddleware);

app.use("/api/score",     scoreRoutes);
app.use("/api/stats",     statsRoutes);
app.use("/api/audit",     auditRoutes);
app.use("/api/stream",    streamRoutes);
app.use("/api/watchlist", watchlistRoutes);
app.use("/api/whois",     whoisRoutes);

app.get("/", (req, res) => res.sendFile(path.join(__dirname, "../public/index.html")));
app.use((req, res) => res.status(404).json({ error: "Not Found", path: req.path }));

if (process.env.SENTRY_DSN) {
  try { app.use(require("@sentry/node").Handlers.errorHandler()); } catch (_) {}
}
app.use(errorMiddleware);

const { startMonitor } = require("./jobs/monitor.job");
startMonitor();

module.exports = app;