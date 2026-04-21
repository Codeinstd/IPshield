const app = require('./server');

const PORT = process.env.PORT || 3000;

fetch("http://localhost:XXXX/api/score")

app.listen(PORT, () => {
  console.log(`
╔══════════════════════════════════════════╗
║   IP Risk Scoring API  v1.0.0            ║
║   Listening on http://localhost:${PORT}     ║
╠══════════════════════════════════════════╣
║  GET  /api/score/:ip                     ║
║  POST /api/score/batch                   ║
║  GET  /api/audit                         ║
║  GET  /api/stats                         ║
║  GET  /api/health                        ║
╚══════════════════════════════════════════╝
  `);
});
const input = document.getElementById("ipInput");
const button = document.getElementById("searchBtn");

button.addEventListener("click", () => {
  searchIP(input.value);
});

input.addEventListener("keyup", (e) => {
  if (e.key === "Enter") {
    searchIP(input.value);
  }
});

function searchIP(ip) {
  console.log("Searching IP:", ip);
  // your API call here
}