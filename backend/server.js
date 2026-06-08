if (process.env.NODE_ENV !== "production") {
  require("dotenv").config();
}
require("./utils/validateEnv")();

const app    = require("./app");
const logger = require("./utils/logger");
const { startWorkers } = require("./jobs/workers");
const { startWatchlistCron } = require("./jobs/watchlistCron");
const path = require("path");
const { initRedis } = require("./store/redis");

const PORT   = parseInt(process.env.PORT || "8080", 10);
const server = app.listen(PORT, "0.0.0.0", () => {
  logger.info(`IPShield running on port ${PORT} [${process.env.NODE_ENV || "development"}]`);
});

require("dotenv").config({
  path: path.join(__dirname, "../.env")
});

app.post("/login", (req, res) => {
    res.json({
        success: true,
        token: "demo-token-123",
        user: {
            email: req.body.email
        }
    });
});

// Graceful shutdown
function shutdown(signal) {
  logger.info(`${signal} received — shutting down gracefully`);
  server.close(() => {
    logger.info("HTTP server closed");
    process.exit(0);
  });
  setTimeout(() => {
    logger.error("Forced shutdown after timeout");
    process.exit(1);
  }, 10000);
}

process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT",  () => shutdown("SIGINT"));

process.on("unhandledRejection", (reason) => {
  logger.error(`Unhandled rejection: ${reason?.message || reason}`, { stack: reason?.stack });
});

process.on("uncaughtException", (err) => {
  logger.error(`Uncaught exception: ${err.message}`, { stack: err.stack });
  process.exit(1);
});

async function startServer() {
  // Initialize Redis — failure is non-fatal
  await initRedis();

  // ... rest of your server startup
  app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
  });
}

startServer();

startWorkers();
startWatchlistCron();