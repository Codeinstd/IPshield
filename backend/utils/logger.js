const winston = require("winston");

const logger = winston.createLogger({
  level: "info",
  transports: [new winston.transports.Console()],
});

module.exports = logger;

const compression = require("compression");
app.use(compression());

const NodeCache = require("node-cache");
const cache = new NodeCache({ stdTTL: 300 });

function getCached(ip) {
  return cache.get(ip);
}

function setCache(ip, data) {
  cache.set(ip, data);
}
app.use("/api", authMiddleware);