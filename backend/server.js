require("dotenv").config();

const express = require("express");
const app     = express();
const PORT    = parseInt(process.env.PORT || "8080", 10);

app.get("/", (req, res) => res.send("IPShield is live ✅"));
app.get("/api/health", (req, res) => res.json({ status: "ok", port: PORT }));

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Server running on port ${PORT}`);
});