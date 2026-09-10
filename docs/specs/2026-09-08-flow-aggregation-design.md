# Flow aggregation and tiered retention

## Problem

FlowSight stores one row per packet. Measured on a live capture:

```
681 MB · 2,565,386 rows over 2.1h  =>  ~1.2M rows/hour (~7.6 GB/day)
distinct 5-tuples: 5,401
```

Three consequences:

1. The database grows without limit. `compliance_settings.retention_days` and
   `auto_purge` are stored and scored, but nothing deletes rows — the compliance
   report certifies a policy that has never run.
2. Historical queries scan millions of near-identical rows.
3. Despite the name, nothing in the system produces flow records. IPFIX is a flow
   protocol; this stores packets.

## Approach

Tiered storage. Raw packets are kept for a short window for the live tail and deep
forensics, then rolled up into hourly-bucketed flow records for long retention.

Aggregation is a periodic SQL job rather than an in-memory flow table or C++-side
aggregation, so the packet hot path is untouched and capture throughput carries no new
risk. Roll-up is plain SQL over aged rows: easy to test, safe to re-run.

## Data model

```sql
CREATE TABLE flows (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    bucket            TEXT NOT NULL,      -- 'YYYY-MM-DDTHH'
    first_seen        TEXT NOT NULL,
    last_seen         TEXT NOT NULL,
    source            TEXT NOT NULL,
    destination       TEXT NOT NULL,
    protocol          TEXT NOT NULL,
    source_port       INTEGER NOT NULL,
    destination_port  INTEGER NOT NULL,
    packets           INTEGER NOT NULL,
    bytes             INTEGER NOT NULL,
    metadata_json     TEXT NOT NULL,
    UNIQUE(bucket, source, destination, protocol, source_port, destination_port)
);
```

**Hourly bucketing.** Collapsing a 5-tuple into a single perpetual row would destroy the
time dimension that histograms, DDoS trends and the Sankey view depend on. One row per
tuple per hour keeps time resolution at ~5,400 rows/hour instead of 1.2M — roughly 220x
rather than the theoretical 475x, which is the right trade.

**The UNIQUE constraint carries the idempotency.** Re-running a roll-up merges through
`ON CONFLICT` instead of duplicating, so an interrupted job is safe to repeat.

**Metadata** is stored as a JSON array of distinct non-empty values, capped at 8 with an
explicit `+N more` marker so truncation is visible rather than silent. Several SNIs or
User-Agents on one connection is normal and must survive aggregation, or forensics stops
working on history.

## Roll-up job

- Runs every `ROLLUP_INTERVAL_MIN` (default 10) and once shortly after startup.
- Targets packets older than `PACKET_RETENTION_HOURS` (default 6).
- Batched (`ROLLUP_BATCH_SIZE`, default 50000) so write locks stay short; SQLite writes
  block capture inserts.
- Groups by `(bucket, source, destination, protocol, source_port, destination_port)`,
  aggregating `MIN(observed_at)`, `MAX(observed_at)`, `COUNT(*)`, `SUM(bytes)` and the
  union of distinct metadata.
- Upsert into `flows` and delete the rolled-up packet ids inside one transaction.

Two invariants the implementation must hold:

- No packet is deleted unless its bytes are already counted in a flow row.
- Running the job twice produces the same result as running it once.

## Read path

The tier boundary must be invisible.

- `/api/history` and the live tail stay on `packets`, unchanged.
- Forensics search becomes a `UNION ALL` across `packets` and `flows`, projecting flows
  into the packet column shape. Results carry `tier` (`packet` / `flow`) and a `packets`
  count so the UI can distinguish one packet from an aggregate of thousands.
- Sankey and matrix read pre-aggregated flows instead of grouping over
  `SELECT * FROM packets ORDER BY id DESC LIMIT 5000`, removing both the cost and the
  silent 5,000-row cap.

## Retention

- Flow purge deletes `WHERE last_seen < now - retention_days`, read from
  `compliance_settings` and gated on `auto_purge`.
- The compliance control stops scoring the stored number and starts asserting observed
  behaviour: last purge time, rows removed, oldest surviving record. A policy that is
  not running reports FAIL.
- `/api/flows/stats` exposes roll-up health — last run, rows in and out, compression
  ratio, database size. A silently broken roll-up otherwise looks like quiet traffic.

## Testing

The job deletes its input, so the tests are about conservation.

1. Conservation: byte and packet totals identical before and after roll-up.
2. Idempotency: two runs equal one run.
3. Crash safety: no packet deleted whose bytes are not already in a flow.
4. Boundaries: rows straddling the retention window and the hour boundary bucket
   correctly.
5. Metadata union: distinct values survive; the cap is marked, not silent.
6. Search continuity: a host is found by the same query before and after roll-up.

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `PACKET_RETENTION_HOURS` | `6` | Age at which packets are rolled up |
| `ROLLUP_INTERVAL_MIN` | `10` | Roll-up job interval |
| `ROLLUP_BATCH_SIZE` | `50000` | Packets per transaction |
| `FLOW_METADATA_CAP` | `8` | Distinct metadata values kept per flow |

Flow retention comes from `compliance_settings.retention_days` (default 90).
