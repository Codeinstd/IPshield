// // Routes to add to routes/blacklist.js
// GET    /api/blacklist          // list all entries (query: severity, status, q)
// POST   /api/blacklist          // add entry
// PUT    /api/blacklist/:id      // update entry
// DELETE /api/blacklist/:id      // single delete
// DELETE /api/blacklist/bulk     // bulk delete (body: { ids: [] })
// GET    /api/blacklist/export?fmt=txt|csv|json|nginx|iptables|cisco