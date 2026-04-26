/**
 * watchlist.store.js
 * Place in: backend/store/watchlist.store.js
 */

const db = require("./db");

// In-memory map — always in sync with DB
const watchlist = new Map();

function bootstrap() {
  if (!db.isAvailable()) return;
  try {
    db.getDb().exec(`
      CREATE TABLE IF NOT EXISTS watchlist (
        ip               TEXT    PRIMARY KEY,
        label            TEXT,
        threshold        INTEGER DEFAULT 30,
        last_score       INTEGER DEFAULT 0,
        last_risk        TEXT    DEFAULT 'UNKNOWN',
        last_checked     INTEGER DEFAULT 0,
        added_at         INTEGER NOT NULL,
        alert_on_change  INTEGER DEFAULT 1
      );
    `);
    const rows = db.getDb().prepare("SELECT * FROM watchlist").all();
    rows.forEach(r => watchlist.set(r.ip, r));
    console.log(`✓ Watchlist loaded: ${watchlist.size} IPs`);
  } catch (err) {
    console.error("Watchlist bootstrap error:", err.message);
  }
}

function addToWatchlist({ ip, label = "", threshold = 30, alertOnChange = true }) {
  const entry = {
    ip,
    label:           label || ip,
    threshold:       parseInt(threshold),
    last_score:      0,
    last_risk:       "UNKNOWN",
    last_checked:    0,
    added_at:        Date.now(),
    alert_on_change: alertOnChange ? 1 : 0
  };

  watchlist.set(ip, entry);

  if (db.isAvailable()) {
    try {
      db.getDb().prepare(`
        INSERT OR REPLACE INTO watchlist
          (ip, label, threshold, last_score, last_risk, last_checked, added_at, alert_on_change)
        VALUES
          (@ip, @label, @threshold, @last_score, @last_risk, @last_checked, @added_at, @alert_on_change)
      `).run(entry);
    } catch (err) {
      console.error("Watchlist insert error:", err.message);
    }
  }
  return entry;
}

function removeFromWatchlist(ip) {
  watchlist.delete(ip);
  if (db.isAvailable()) {
    try {
      db.getDb().prepare("DELETE FROM watchlist WHERE ip = ?").run(ip);
    } catch (err) {
      console.error("Watchlist delete error:", err.message);
    }
  }
}

function updateWatchlistEntry(ip, updates) {
  const entry = watchlist.get(ip);
  if (!entry) return;
  Object.assign(entry, updates);
  watchlist.set(ip, entry);
  if (db.isAvailable()) {
    try {
      db.getDb().prepare(`
        UPDATE watchlist
        SET last_score = @last_score, last_risk = @last_risk, last_checked = @last_checked
        WHERE ip = @ip
      `).run({ ip, ...updates });
    } catch (err) {
      console.error("Watchlist update error:", err.message);
    }
  }
}

function getWatchlist() {
  return Array.from(watchlist.values()).sort((a, b) => b.last_score - a.last_score);
}

function isWatched(ip)    { return watchlist.has(ip); }
function getWatchedIP(ip) { return watchlist.get(ip) || null; }
function watchlistSize()  { return watchlist.size; }

try { bootstrap(); } catch (_) {}

module.exports = {
  addToWatchlist, removeFromWatchlist, updateWatchlistEntry,
  getWatchlist, isWatched, getWatchedIP, watchlistSize
};