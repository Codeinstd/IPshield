const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const morgan = require("morgan");
const path = require("path");


const scoreRoutes = require("./routes/score.routes");
const statsRoutes = require("./routes/stats.routes");
const auditRoutes = require("./routes/audit.routes");
const errorMiddleware = require("./middleware/error.middleware");

// rate limit 
const rateLimit = require("express-rate-limit");

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: "Too many requests, slow down."
});


const app = express();

// Middleware
app.use(helmet());
app.use(cors());
app.use(express.json());
app.use(morgan("dev"));




app.use("/api/", limiter); // ✅ NOW SAFE


// ✅ CRITICAL: Serve static files FIRST
app.use(express.static(path.join(__dirname, "../public")));

// (Optional debug: confirm path)
console.log("Serving static from:", path.join(__dirname, "../public"));

// API routes
app.use("/api/score", scoreRoutes);
app.use("/api/stats", statsRoutes);
app.use("/api/audit", auditRoutes);

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


// logger
const logger = require("./utils/logger");

logger.info("Server started");

// Error handler
app.use(errorMiddleware);

// const compression = require("compression");
// backend/app.js
const compression = require("compression");

app.use(compression());


// Promise.race([apiCall(), timeout(3000)])

module.exports = app;