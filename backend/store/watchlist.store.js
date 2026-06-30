const db = require("./db");

// In-memory map — always in sync with DB
const watchlist = new Map();

async function bootstrap() {
  try {
    await db.query(`
      CREATE TABLE IF NOT EXISTS watchlist (
        ip              TEXT PRIMARY KEY,
        label           TEXT,
        threshold       INTEGER DEFAULT 30,
        last_score      INTEGER DEFAULT 0,
        last_risk       TEXT    DEFAULT 'UNKNOWN',
        last_checked    TIMESTAMPTZ,
        added_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        alert_on_change BOOLEAN NOT DEFAULT TRUE
      )
    `);

    const result = await db.query("SELECT * FROM watchlist");
    result.rows.forEach((r) => {
      watchlist.set(r.ip, { ...r, alert_on_change: !!r.alert_on_change });
    });
    console.log(`✓ Watchlist loaded: ${watchlist.size} IPs`);
  } catch (err) {
    console.error("Watchlist bootstrap error:", err.message);
  }
}

async function addToWatchlist({ ip, label = "", threshold = 30, alertOnChange = true }) {
  const entry = {
    ip,
    label:          label || ip,
    threshold:      parseInt(threshold, 10),
    last_score:     0,
    last_risk:      "UNKNOWN",
    last_checked:   null,
    added_at:       new Date(),
    alert_on_change: alertOnChange
  };

  watchlist.set(ip, entry);

  try {
    await db.query(
      `INSERT INTO watchlist
         (ip, label, threshold, last_score, last_risk, last_checked, added_at, alert_on_change)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
       ON CONFLICT (ip) DO UPDATE SET
         label           = EXCLUDED.label,
         threshold       = EXCLUDED.threshold,
         last_score      = EXCLUDED.last_score,
         last_risk       = EXCLUDED.last_risk,
         last_checked    = EXCLUDED.last_checked,
         added_at        = EXCLUDED.added_at,
         alert_on_change = EXCLUDED.alert_on_change`,
      [entry.ip, entry.label, entry.threshold, entry.last_score,
       entry.last_risk, entry.last_checked, entry.added_at, entry.alert_on_change]
    );
  } catch (err) {
    console.error("Watchlist insert error:", err.message);
  }

  return entry;
}

async function removeFromWatchlist(ip) {
  watchlist.delete(ip);
  try {
    await db.query("DELETE FROM watchlist WHERE ip = $1", [ip]);
  } catch (err) {
    console.error("Watchlist delete error:", err.message);
  }
}

async function updateWatchlistEntry(ip, updates) {
  const entry = watchlist.get(ip);
  if (!entry) return;
  Object.assign(entry, updates);
  watchlist.set(ip, entry);
  try {
    await db.query(
      `UPDATE watchlist
       SET last_score = $1, last_risk = $2, last_checked = $3
       WHERE ip = $4`,
      [entry.last_score, entry.last_risk, entry.last_checked, ip]
    );
  } catch (err) {
    console.error("Watchlist update error:", err.message);
  }
}

function getWatchlist() {
  return Array.from(watchlist.values()).sort((a, b) => b.last_score - a.last_score);
}

function isWatched(ip)    { return watchlist.has(ip); }
function getWatchedIP(ip) { return watchlist.get(ip) || null; }
function watchlistSize()  { return watchlist.size; }

bootstrap().catch(() => {});

module.exports = {
  addToWatchlist, removeFromWatchlist, updateWatchlistEntry,
  getWatchlist, isWatched, getWatchedIP, watchlistSize
};