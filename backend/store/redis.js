const redis = require("redis");

let client = null;
let connectPromise = null;
let connected = false;

async function connect() {
  if (!process.env.REDIS_URL) {
    console.warn(
      "[redis] REDIS_URL not set — running without Redis"
    );
    return null;
  }

  if (connected && client) return client;

  if (connectPromise) return connectPromise;

  connectPromise = (async () => {
    try {
      client = redis.createClient({
        url: process.env.REDIS_URL,
        socket: {
          reconnectStrategy: (retries) => {
            // keep retrying safely (no permanent disable)
            return Math.min(retries * 1000, 30000);
          },
          connectTimeout: 5000,
        },
      });

      client.on("error", (err) => {
        connected = false;
        console.error("[redis] error:", err.message);
      });

      client.on("ready", () => {
        connected = true;
        console.log("[redis] ready");
      });

      client.on("end", () => {
        connected = false;
        console.warn("[redis] disconnected");
      });

      await client.connect();

      connected = true;
      return client;
    } catch (err) {
      connected = false;
      client = null;
      console.warn(
        "[redis] failed — running without Redis:",
        err.message
      );
      return null;
    }
  })();

  return connectPromise;
}

// safe getter
function getRedis() {
  return connected && client ? client : null;
}

function isRedisConnected() {
  return connected;
}

// safe bootstrap (never crashes app)
async function initRedis() {
  try {
    await connect();
  } catch (err) {
    console.warn("[redis] init failed:", err.message);
  }
}

module.exports = {
  getRedis,
  isRedisConnected,
  initRedis,
};