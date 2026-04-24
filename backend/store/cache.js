const TTL_MS = 1000 * 60 * 15; // 15 minutes

const store = new Map();

function get(key) {
  const entry = store.get(key);
  if (!entry) return null;
  if (Date.now() - entry.ts > TTL_MS) { store.delete(key); return null; }
  return entry.data;
}

function set(key, data) {
  store.set(key, { data, ts: Date.now() });
}

function size() { return store.size; }

function flush() { store.clear(); }

module.exports = { get, set, size, flush };