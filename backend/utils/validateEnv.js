// backend/utils/validateEnv.js
function validateEnv() {
  const missing = REQUIRED.filter(k => !process.env[k]);
  if (missing.length) {
    console.warn("⚠ Missing env vars:", missing.join(", "));
    console.warn("App will start but some features may not work.");
    // Don't process.exit — let it run
  } else {
    console.log("✓ Environment validated");
  }
}
module.exports = validateEnv;