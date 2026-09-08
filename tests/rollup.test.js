// Exercises the real compiled roll-up module against a scratch database.
// The job deletes its own input, so these tests are about conservation.
const { DatabaseSync } = require('node:sqlite');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { createRollup, mergeMetadata } = require(path.join(__dirname, '..', 'dist', 'rollup.js'));

let failures = 0;
const check = (ok, what, detail = '') => {
  console.log(`  ${ok ? 'PASS' : 'FAIL'}  ${what}${detail ? '  ' + detail : ''}`);
  if (!ok) failures++;
};

function freshDb() {
  const file = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'rollup-')), 'test.sqlite');
  const db = new DatabaseSync(file);
  db.exec(`
    CREATE TABLE packets (
      id INTEGER PRIMARY KEY AUTOINCREMENT, observed_at TEXT NOT NULL, source TEXT NOT NULL,
      destination TEXT NOT NULL, protocol TEXT NOT NULL, source_port INTEGER NOT NULL,
      destination_port INTEGER NOT NULL, bytes INTEGER NOT NULL, metadata TEXT NOT NULL);
    CREATE TABLE flows (
      id INTEGER PRIMARY KEY AUTOINCREMENT, bucket TEXT NOT NULL, first_seen TEXT NOT NULL,
      last_seen TEXT NOT NULL, source TEXT NOT NULL, destination TEXT NOT NULL,
      protocol TEXT NOT NULL, source_port INTEGER NOT NULL, destination_port INTEGER NOT NULL,
      packets INTEGER NOT NULL, bytes INTEGER NOT NULL, metadata_json TEXT NOT NULL,
      UNIQUE(bucket, source, destination, protocol, source_port, destination_port));
    CREATE TABLE rollup_state (id INTEGER PRIMARY KEY DEFAULT 1, last_run TEXT,
      last_packets_in INTEGER NOT NULL DEFAULT 0, last_flows_out INTEGER NOT NULL DEFAULT 0,
      total_packets_rolled INTEGER NOT NULL DEFAULT 0, last_purge TEXT,
      last_purge_removed INTEGER NOT NULL DEFAULT 0);
    CREATE TABLE compliance_settings (id INTEGER PRIMARY KEY DEFAULT 1,
      retention_days INTEGER NOT NULL DEFAULT 90, auto_purge INTEGER NOT NULL DEFAULT 1,
      min_tls_version TEXT NOT NULL DEFAULT 'TLSv1.2', updated_at TEXT NOT NULL);
    INSERT INTO rollup_state (id) VALUES (1);
    INSERT INTO compliance_settings (id, updated_at) VALUES (1, datetime('now'));
  `);
  return db;
}

const NOW = Date.parse('2026-09-09T12:00:00.000Z');
const hoursAgo = (h) => new Date(NOW - h * 3600_000).toISOString();

function seed(db, rows) {
  const ins = db.prepare('INSERT INTO packets (observed_at, source, destination, protocol, source_port, destination_port, bytes, metadata) VALUES (?,?,?,?,?,?,?,?)');
  for (const r of rows) ins.run(r.at, r.src || '10.0.0.1', r.dst || '10.0.0.2', r.proto || 'TCP', r.sp || 1234, r.dp || 443, r.bytes || 100, r.meta || 'No application metadata');
}

console.log('\n[1] conservation: bytes and packet counts survive roll-up');
{
  const db = freshDb();
  const rows = [];
  for (let i = 0; i < 500; i++) rows.push({ at: hoursAgo(24 + (i % 5)), bytes: 10 + i, dp: 400 + (i % 7) });
  seed(db, rows);
  const before = db.prepare('SELECT COUNT(*) c, SUM(bytes) b FROM packets').get();
  createRollup(db).runRollup(NOW);
  const after = db.prepare('SELECT SUM(packets) p, SUM(bytes) b FROM flows').get();
  const left = db.prepare('SELECT COUNT(*) c FROM packets').get().c;
  check(after.p === before.c, 'packet count preserved', `${before.c} -> ${after.p}`);
  check(after.b === before.b, 'byte total preserved', `${before.b} -> ${after.b}`);
  check(left === 0, 'aged packets removed', `${left} left`);
  const flows = db.prepare('SELECT COUNT(*) c FROM flows').get().c;
  console.log(`        compression: ${before.c} packets -> ${flows} flows (${(before.c / flows).toFixed(1)}x)`);
}

console.log('\n[2] idempotency: running twice equals running once');
{
  const db = freshDb();
  const rows = [];
  for (let i = 0; i < 300; i++) rows.push({ at: hoursAgo(30), bytes: 50, dp: 400 + (i % 3) });
  seed(db, rows);
  const r = createRollup(db);
  r.runRollup(NOW);
  const first = db.prepare('SELECT COUNT(*) c, SUM(packets) p, SUM(bytes) b FROM flows').get();
  r.runRollup(NOW);
  r.runRollup(NOW);
  const third = db.prepare('SELECT COUNT(*) c, SUM(packets) p, SUM(bytes) b FROM flows').get();
  check(JSON.stringify(first) === JSON.stringify(third), 'three runs equal one run', JSON.stringify(third));
}

console.log('\n[3] retention window boundary');
{
  const db = freshDb();
  seed(db, [
    { at: hoursAgo(7), bytes: 11 },   // older than the 6h window -> rolled
    { at: hoursAgo(1), bytes: 22 },   // inside the window -> kept as a packet
  ]);
  createRollup(db).runRollup(NOW);
  const kept = db.prepare('SELECT bytes FROM packets').all();
  const rolled = db.prepare('SELECT bytes FROM flows').all();
  check(kept.length === 1 && kept[0].bytes === 22, 'recent packet left in place');
  check(rolled.length === 1 && rolled[0].bytes === 11, 'aged packet rolled up');
}

console.log('\n[4] hourly bucketing keeps the time dimension');
{
  const db = freshDb();
  seed(db, [
    { at: '2026-09-08T10:15:00.000Z', bytes: 5 },
    { at: '2026-09-08T10:45:00.000Z', bytes: 5 },
    { at: '2026-09-08T11:05:00.000Z', bytes: 5 },
  ]);
  createRollup(db).runRollup(NOW);
  const buckets = db.prepare('SELECT bucket, packets FROM flows ORDER BY bucket').all();
  check(buckets.length === 2, 'same tuple split across two hour buckets', JSON.stringify(buckets.map(b => b.bucket)));
  check(buckets[0].packets === 2 && buckets[1].packets === 1, 'packets land in the right bucket');
}

console.log('\n[5] metadata union and visible cap');
{
  const db = freshDb();
  const rows = [];
  for (let i = 0; i < 12; i++) rows.push({ at: hoursAgo(20), bytes: 1, meta: `app=TLS;sni=host${i}.test` });
  rows.push({ at: hoursAgo(20), bytes: 1 });   // 'No application metadata' must not be stored
  seed(db, rows);
  createRollup(db).runRollup(NOW);
  const meta = JSON.parse(db.prepare('SELECT metadata_json FROM flows').get().metadata_json);
  check(meta.some(v => v.includes('host0.test')), 'distinct SNI values preserved');
  check(!meta.includes('No application metadata'), 'empty metadata not stored');
  check(meta.some(v => /^\+\d+ more$/.test(v)), 'cap is marked, not silent', JSON.stringify(meta.slice(-1)));
  check(mergeMetadata(JSON.stringify(['a', '+3 more']), ['b']) === JSON.stringify(['a', 'b', '+3 more']), 'merge carries prior truncation count');
}

console.log('\n[6] retention purge honours compliance_settings');
{
  const db = freshDb();
  seed(db, [{ at: '2025-01-01T00:00:00.000Z', bytes: 1 }, { at: hoursAgo(48), bytes: 1 }]);
  const r = createRollup(db);
  r.runRollup(NOW);
  check(db.prepare('SELECT COUNT(*) c FROM flows').get().c === 2, 'two flows before purge');
  const removed = r.purgeExpiredFlows(NOW);
  check(removed === 1, 'expired flow purged', `removed=${removed}`);
  check(db.prepare('SELECT COUNT(*) c FROM flows').get().c === 1, 'in-window flow retained');
  db.prepare('UPDATE compliance_settings SET auto_purge = 0 WHERE id = 1').run();
  seed(db, [{ at: '2025-01-01T00:00:00.000Z', bytes: 1, dp: 999 }]);
  r.runRollup(NOW);
  const before = db.prepare('SELECT COUNT(*) c FROM flows').get().c;
  r.purgeExpiredFlows(NOW);
  check(db.prepare('SELECT COUNT(*) c FROM flows').get().c === before, 'auto_purge=0 disables purging');
}

console.log('\n[7] no packet deleted without being counted');
{
  const db = freshDb();
  seed(db, [{ at: hoursAgo(10), bytes: 7 }, { at: hoursAgo(10), bytes: 9 }]);
  const total = db.prepare('SELECT SUM(bytes) b FROM packets').get().b;
  createRollup(db).runRollup(NOW);
  const acct = db.prepare('SELECT COALESCE(SUM(bytes),0) b FROM flows').get().b
             + db.prepare('SELECT COALESCE(SUM(bytes),0) b FROM packets').get().b;
  check(acct === total, 'every byte accounted for across both tiers', `${total} -> ${acct}`);
}

console.log(failures ? '\n=== ROLLUP TESTS FAILED ===' : '\n=== ROLLUP TESTS PASSED ===');
process.exit(failures ? 1 : 0);
