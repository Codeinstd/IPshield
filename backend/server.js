/**
 * server.js
 * Place in: backend/server.js
 */

// REPLACE the top of server.js with:
if (process.env.NODE_ENV !== "production") {
  require("dotenv").config();
}
require("./utils/validateEnv")();

require("./utils/validateEnv")(); // crash fast on missing env vars

const app    = require("./app");
const logger = require("./utils/logger");

const PORT = parseInt(process.env.PORT || "3000", 10);

const server = app.listen(PORT, () => {
  logger.info(`🚀 IPShield running on port ${PORT} [${process.env.NODE_ENV || "development"}]`);
});

// ── Graceful shutdown ─────────────────────────────────────────────────────────
function shutdown(signal) {
  logger.info(`${signal} received — shutting down gracefully`);
  server.close(() => {
    logger.info("HTTP server closed");
    try {
      // Close SQLite connection cleanly
      const db = require("./store/db");
      if (db.isAvailable()) db.close?.();
    } catch (_) {}
    process.exit(0);
  });

  // Force exit after 10s if connections hang
  setTimeout(() => {
    logger.error("Forced shutdown after timeout");
    process.exit(1);
  }, 10000);
}

process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT",  () => shutdown("SIGINT"));

// ── Unhandled rejections ──────────────────────────────────────────────────────
process.on("unhandledRejection", (reason) => {
  logger.error("Unhandled rejection:", reason);
});

process.on("uncaughtException", (err) => {
  logger.error("Uncaught exception:", err);
  process.exit(1);
});