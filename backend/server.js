require("dotenv").config(); // MUST be first

console.log("Loaded API KEY:", process.env.ABUSE_IPDB_KEY);

const app = require("./app");

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`🚀 IPShield API running on port ${PORT}`);
});