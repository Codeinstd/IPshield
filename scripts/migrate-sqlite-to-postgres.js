
import Database from 'better-sqlite3';
import pg from 'pg';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SQLITE_PATH = process.env.SQLITE_PATH ?? path.join(__dirname, '..', 'ipshield.db');

if (!process.env.DATABASE_URL) {
  console.error('❌  Set DATABASE_URL before running this script');
  process.exit(1);
}

const sqlite = new Database(SQLITE_PATH, { readonly: true });
const pgPool = new pg.Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
});

// ─── helpers 

function log(msg) { console.log(`  ${msg}`); }

async function pgExec(sql, params = []) {
  return pgPool.query(sql, params);
}

function sqliteTables() {
  return sqlite
    .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
    .all()
    .map(r => r.name);
}

// ─── per-table migration handlers 

async function migrateAuditLog(rows) {
  log(`audit_log: ${rows.length} rows`);
  for (const r of rows) {
    await pgExec(
      `INSERT INTO audit_log
         (ip, score, risk_level, action, is_proxy, is_tor, is_datacenter,
          country, isp, asn, cached, scored_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
       ON CONFLICT DO NOTHING`,
      [r.ip, r.score, r.risk_level, r.action,
       Boolean(r.is_proxy), Boolean(r.is_tor), Boolean(r.is_datacenter),
       r.country, r.isp, r.asn, Boolean(r.cached),
       r.scored_at ?? new Date().toISOString()]
    );
  }
}

async function migrateBlacklist(rows) {
  log(`blacklist: ${rows.length} rows`);
  for (const r of rows) {
    const tags = r.tags ? JSON.parse(r.tags) : [];
    await pgExec(
      `INSERT INTO blacklist
         (ip, severity, category, reason, added_by, added_at, expires_at, tags)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
       ON CONFLICT (ip) DO NOTHING`,
      [r.ip, r.severity ?? 'HIGH', r.category, r.reason,
       r.added_by ?? 'analyst', r.added_at, r.expires_at, tags]
    );
  }
}

async function migrateCases(rows) {
  log(`cases: ${rows.length} rows`);
  for (const r of rows) {
    const tags = r.tags ? JSON.parse(r.tags) : [];
    await pgExec(
      `INSERT INTO cases
         (id, title, description, severity, status, assigned_to, tags,
          created_at, updated_at, closed_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
       ON CONFLICT DO NOTHING`,
      [r.id, r.title, r.description, r.severity ?? 'MEDIUM',
       r.status ?? 'Open', r.assigned_to, tags,
       r.created_at, r.updated_at ?? r.created_at, r.closed_at]
    );
  }
  // Sync the serial sequence so new inserts don't collide with migrated IDs
  await pgExec(`SELECT setval('cases_id_seq', COALESCE((SELECT MAX(id) FROM cases), 0))`);
}

async function migrateCaseIps(rows) {
  log(`case_ips: ${rows.length} rows`);
  for (const r of rows) {
    await pgExec(
      `INSERT INTO case_ips (id, case_id, ip, score, risk_level, note, added_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7)
       ON CONFLICT DO NOTHING`,
      [r.id, r.case_id, r.ip, r.score, r.risk_level, r.note, r.added_at]
    );
  }
  await pgExec(`SELECT setval('case_ips_id_seq', COALESCE((SELECT MAX(id) FROM case_ips), 0))`);
}

async function migrateCaseNotes(rows) {
  log(`case_notes: ${rows.length} rows`);
  for (const r of rows) {
    await pgExec(
      `INSERT INTO case_notes (id, case_id, note, author, created_at)
       VALUES ($1,$2,$3,$4,$5)
       ON CONFLICT DO NOTHING`,
      [r.id, r.case_id, r.note, r.author ?? 'analyst', r.created_at]
    );
  }
  await pgExec(`SELECT setval('case_notes_id_seq', COALESCE((SELECT MAX(id) FROM case_notes), 0))`);
}

async function migrateWatchlist(rows) {
  log(`watchlist: ${rows.length} rows`);
  for (const r of rows) {
    await pgExec(
      `INSERT INTO watchlist
         (ip, label, threshold, last_score, last_risk,
          last_checked, added_at, alert_on_change)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
       ON CONFLICT (ip) DO NOTHING`,
      [r.ip, r.label, r.threshold ?? 30, r.last_score, r.last_risk,
       r.last_checked ? new Date(r.last_checked * 1000).toISOString() : null,
       r.added_at ? new Date(r.added_at * 1000).toISOString() : new Date().toISOString(),
       Boolean(r.alert_on_change)]
    );
  }
}

// ─── main 

const TABLE_HANDLERS = {
  audit_log:   migrateAuditLog,
  blacklist:   migrateBlacklist,
  cases:       migrateCases,
  case_ips:    migrateCaseIps,
  case_notes:  migrateCaseNotes,
  watchlist:   migrateWatchlist,
};

async function run() {
  console.log('\n🚀  IPShield SQLite → PostgreSQL migration\n');
  console.log(`   Source: ${SQLITE_PATH}`);
  console.log(`   Target: ${process.env.DATABASE_URL.replace(/:\/\/.*@/, '://***@')}\n`);

  const tables = sqliteTables();
  console.log(`Found SQLite tables: ${tables.join(', ')}\n`);

  for (const [table, handler] of Object.entries(TABLE_HANDLERS)) {
    if (!tables.includes(table)) {
      log(`${table}: not found in SQLite, skipping`);
      continue;
    }
    try {
      const rows = sqlite.prepare(`SELECT * FROM ${table}`).all();
      await handler(rows);
      log(`${table}: ✓`);
    } catch (err) {
      console.error(`\n❌  Failed on table "${table}":`, err.message);
      process.exit(1);
    }
  }

  console.log('\n✅  Migration complete\n');
  await pgPool.end();
  sqlite.close();
}

run().catch(err => {
  console.error('Fatal:', err);
  process.exit(1);
});
