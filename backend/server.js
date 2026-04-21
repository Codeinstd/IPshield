require("dotenv").config();

const app = require("./app"); // ✅ use existing app

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`🚀 IPShield API running on port ${PORT}`);
});