const app = require('./server');

const PORT = process.env.PORT || 3000;

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
