const redis = require("redis");

let client     = null;
let connected  = false;
let connecting = false;

async function connect() {
  if (!process.env.REDIS_URL) {
    console.warn("[redis] REDIS_URL not set — Redis disabled, running without cache");
    return null;
  }

  if (connected && client) return client;
  if (connecting)          return null;

  connecting = true;

  try {
    client = redis.createClient({
      url: process.env.REDIS_URL,
      socket: {
        reconnectStrategy: (retries) => {
          // Stop retrying after 3 attempts — don't spam logs
          if (retries >= 3) {
            console.warn("[redis] giving up reconnection after 3 attempts — running without cache");
            return false;
          }
          return Math.min(retries * 500, 3000);
        },
        connectTimeout: 5000, 
      },
    });

    client.on("error", (err) => {
      // Only log once, not every retry
      if (connected || connecting) {
        console.error("[redis] error:", err.message);
      }
      connected  = false;
      connecting = false;
    });

    client.on("connect", () => {
      console.log("[redis] connected successfully");
      connected  = true;
      connecting = false;
    });

    client.on("end", () => {
      console.warn("[redis] connection closed");
      connected  = false;
      connecting = false;
    });

    await client.connect();
    connected  = true;
    connecting = false;
    return client;

  } catch (err) {
    console.error("[redis] failed to connect:", err.message);
    console.warn("[redis] app will continue without Redis — caching and queues disabled");
    client     = null;
    connected  = false;
    connecting = false;
    return null;
  }
}

// Synchronous getter — returns null if not connected
function getRedis() {
  if (connected && client) return client;
  return null;
}

// Check status
function isRedisConnected() {
  return connected;
}

// Initialize on startup — never throws
async function initRedis() {
  try {
    await connect();
  } catch (_) {
    console.warn("[redis] init failed — continuing without Redis");
  }
}

module.exports = { getRedis, isRedisConnected, initRedis };