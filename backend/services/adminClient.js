const axios = require("axios");

const ADMIN_KEY = process.env.ADMIN_API_KEY;
const API_BASE  = process.env.INTERNAL_API_URL || "http://localhost:3000";

async function getStats() {
  const res = await axios.get(`${API_BASE}/api/v1/stats`, {  // ← await, don't return early
    headers: { "x-api-key": ADMIN_KEY },
  });
  return res.data;  // ← now reachable
}

module.exports = { getStats };