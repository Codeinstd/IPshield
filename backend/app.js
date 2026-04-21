const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const morgan = require("morgan");
const path = require("path");

const scoreRoutes = require("./routes/score.routes");
const statsRoutes = require("./routes/stats.routes");
const auditRoutes = require("./routes/audit.routes");
const errorMiddleware = require("./middleware/error.middleware");

const app = express();

// Middleware
app.use(helmet());
app.use(cors());
app.use(express.json());
app.use(morgan("dev"));

// ✅ CRITICAL: Serve static files FIRST
app.use(express.static(path.join(__dirname, "../public")));

// (Optional debug: confirm path)
console.log("Serving static from:", path.join(__dirname, "../public"));

// API routes
app.use("/api/score", scoreRoutes);
app.use("/api/stats", statsRoutes);
app.use("/api/audit", auditRoutes);


app.get("/api/score/:ip", (req, res) => {
  res.json({
    ip: req.params.ip,
    score: 42,
    riskLevel: "MEDIUM",
    action: "MONITOR",
    signals: [],
    geo: {},
    network: { type: "unknown", isDatacenter: false },
    behavior: { requestsLast5Min: 1, velocityLabel: "LOW", firstSeen: Date.now() },
    meta: { processingMs: 12, scoredAt: Date.now() }
  });
});

// Health check
app.get("/api/health", (req, res) => {
  res.json({ status: "ok 🚀" });
});

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "../public/index.html"));
});

// ❗ 404 MUST BE LAST
app.use((req, res) => {
  res.status(404).json({ message: "Route not found" });
});

const rateLimit = require("express-rate-limit");

app.use(rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100
}));

// Error handler
app.use(errorMiddleware);

module.exports = app;