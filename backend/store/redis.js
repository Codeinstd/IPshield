
const Redis = require("ioredis");

let client = null;

function getRedis() {
  if (client) return client;

  if (!process.env.REDIS_URL) {
    console.warn("[redis] REDIS_URL not set — Phase 2 features disabled");
    return null;
  }

  client = new Redis(process.env.REDIS_URL, {
    maxRetriesPerRequest: null, // required by BullMQ
    enableReadyCheck:     false,
    lazyConnect:          true,
  });

  client.on("connect",  () => console.log("✓ Redis connected"));
  client.on("error",    (err) => console.error("[redis] Error:", err.message));
  client.on("close",    () => console.warn("[redis] Connection closed"));

  return client;
}

module.exports = { getRedis };