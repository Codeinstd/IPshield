const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const morgan = require("morgan");
const compression = require("compression");
const path = require("path");
const rateLimit = require("express-rate-limit");

const scoreRoutes = require("./routes/score.routes");
const statsRoutes = require("./routes/stats.routes");
const auditRoutes = require("./routes/audit.routes");
const streamRoutes = require("./routes/stream.routes");
const errorMiddleware = require("./middleware/error.middleware");
const logger = require("./utils/logger");

const app = express();

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: "Too many requests, slow down."
});

// ✅ 1. Core middleware first
app.use(helmet());
app.use(cors());
app.use(compression()); // must be before routes
app.use(express.json());
app.use(morgan("dev"));
app.use("/api/", limiter);

// ✅ 2. Static files
app.use(express.static(path.join(__dirname, "../public")));

// ✅ 3. API routes
app.use("/api/score", scoreRoutes);
app.use("/api/stats", statsRoutes);
app.use("/api/audit", auditRoutes);
app.use("/api/stream", streamRoutes);

// ✅ 4. Health check
app.get("/api/health", (req, res) => {
  res.json({ status: "ok 🚀" });
});

// ✅ 5. SPA fallback
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "../public/index.html"));
});

// ✅ 6. 404 — must be BEFORE error handler, AFTER all routes
app.use((req, res) => {
  res.status(404).json({ message: "Route not found" });
});

// ✅ 7. Error handler — must be LAST, needs 4 params (err, req, res, next)
app.use(errorMiddleware);

logger.info("Server started");

module.exports = app;