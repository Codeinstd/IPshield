// backend/utils/validateEnv.js
const REQUIRED = ["ABUSE_IPDB_KEY", "IPSHIELD_API_KEY"];

function validateEnv() {
  const missing = REQUIRED.filter(k => !process.env[k]);
  if (missing.length) {
    console.warn("⚠ Missing env vars:", missing.join(", "));
    console.warn("App will start but some features may not work.");
  } else {
    console.log("✓ Environment validated");
  }
}

module.exports = validateEnv;