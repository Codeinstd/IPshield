const axios = require("axios");

async function getAbuseData(ip) {
  const response = await axios.get(
    "https://api.abuseipdb.com/api/v2/check",
    {
      params: {
        ipAddress: ip,
        maxAgeInDays: 90
      },
      headers: {
        Key: process.env.ABUSEIPDB_KEY, // ✅ NOT Authorization
        Accept: "application/json"
      }
    }
  );

  return response.data.data;
}
console.log("Loaded key:", process.env.ABUSEIPDB_KEY);

module.exports = { getAbuseData };