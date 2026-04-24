require("dotenv").config();
require("./utils/validateEnv")();

const app    = require("./app");
const logger = require("./utils/logger");

const PORT = parseInt(process.env.PORT || "3000", 10);

const server = app.listen(PORT, "0.0.0.0", () => {
  logger.info(`🚀 IPShield running on port ${PORT} [${process.env.NODE_ENV || "development"}]`);
});

function shutdown(signal) {
  logger.info(`${signal} received — shutting down gracefully`);
  server.close(() => {
    logger.info("HTTP server closed");
    process.exit(0);
  });
  setTimeout(() => process.exit(1), 10000);
}

process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT",  () => shutdown("SIGINT"));
process.on("unhandledRejection", (reason) => logger.error("Unhandled rejection:", reason));
process.on("uncaughtException",  (err)    => { logger.error("Uncaught exception:", err); process.exit(1); });