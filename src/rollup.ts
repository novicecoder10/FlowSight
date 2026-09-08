import type { DatabaseSync } from 'node:sqlite';

// Packets are kept briefly for the live tail and deep forensics, then rolled up into
// hourly-bucketed flow records for long retention. The roll-up is a periodic SQL job,
// so the packet hot path is untouched and capture throughput carries no new risk.
export const PACKET_RETENTION_HOURS = Number(process.env.PACKET_RETENTION_HOURS || 6);
export const ROLLUP_INTERVAL_MIN = Number(process.env.ROLLUP_INTERVAL_MIN || 10);
export const ROLLUP_BATCH_SIZE = Number(process.env.ROLLUP_BATCH_SIZE || 50000);
export const FLOW_METADATA_CAP = Number(process.env.FLOW_METADATA_CAP || 8);

export type RollupResult = { packetsIn: number; flowsOut: number };

export type Rollup = {
    runRollup(nowMs?: number): RollupResult;
    runRollupBatch(cutoffIso: string): RollupResult;
    purgeExpiredFlows(nowMs?: number): number;
    state(): any;
};

// Distinct metadata values are preserved so a search for an SNI still resolves after the
// packets carrying it are gone. The cap is marked rather than applied silently.
export function mergeMetadata(existingJson: string | undefined, incoming: string[], cap = FLOW_METADATA_CAP): string {
    const values = new Set<string>();
    let truncated = 0;
    const absorb = (list: string[]) => {
        for (const value of list) {
            const match = /^\+(\d+) more$/.exec(value);
            if (match) { truncated += Number(match[1]); continue; }
            if (value && value !== 'No application metadata') values.add(value);
        }
    };
    if (existingJson) {
        try { absorb(JSON.parse(existingJson) as string[]); } catch { /* malformed rows are ignored */ }
    }
    absorb(incoming);
    const kept = Array.from(values).slice(0, cap);
    const dropped = truncated + Math.max(0, values.size - kept.length);
    if (dropped > 0) kept.push(`+${dropped} more`);
    return JSON.stringify(kept);
}

export function createRollup(database: DatabaseSync): Rollup {
    const upsertFlow = database.prepare(`
        INSERT INTO flows (bucket, first_seen, last_seen, source, destination, protocol, source_port, destination_port, packets, bytes, metadata_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(bucket, source, destination, protocol, source_port, destination_port) DO UPDATE SET
            first_seen = MIN(first_seen, excluded.first_seen),
            last_seen  = MAX(last_seen, excluded.last_seen),
            packets    = packets + excluded.packets,
            bytes      = bytes + excluded.bytes,
            metadata_json = excluded.metadata_json`);
    const selectFlowMetadata = database.prepare('SELECT metadata_json FROM flows WHERE bucket = ? AND source = ? AND destination = ? AND protocol = ? AND source_port = ? AND destination_port = ?');
    const selectAged = database.prepare('SELECT id, observed_at, source, destination, protocol, source_port, destination_port, bytes, metadata FROM packets WHERE observed_at < ? ORDER BY id LIMIT ?');
    const updateRollupState = database.prepare('UPDATE rollup_state SET last_run = ?, last_packets_in = ?, last_flows_out = ?, total_packets_rolled = total_packets_rolled + ? WHERE id = 1');
    const updatePurgeState = database.prepare('UPDATE rollup_state SET last_purge = ?, last_purge_removed = ? WHERE id = 1');
    const selectState = database.prepare('SELECT * FROM rollup_state WHERE id = 1');
    const selectSettings = database.prepare('SELECT retention_days, auto_purge FROM compliance_settings WHERE id = 1');

    // One batch: aggregate aged packets into flows and delete exactly what was
    // aggregated, in a single transaction. A crash can therefore never drop packets
    // whose bytes were not already counted.
    function runRollupBatch(cutoffIso: string): RollupResult {
        const rows = selectAged.all(cutoffIso, ROLLUP_BATCH_SIZE) as any[];
        if (rows.length === 0) return { packetsIn: 0, flowsOut: 0 };

        type Agg = {
            bucket: string; first: string; last: string;
            source: string; destination: string; protocol: string;
            sourcePort: number; destinationPort: number;
            packets: number; bytes: number; metadata: Set<string>;
        };
        const groups = new Map<string, Agg>();
        const ids: number[] = [];

        for (const row of rows) {
            ids.push(row.id);
            const bucket = String(row.observed_at).slice(0, 13);   // YYYY-MM-DDTHH
            const key = `${bucket}|${row.source}|${row.destination}|${row.protocol}|${row.source_port}|${row.destination_port}`;
            let agg = groups.get(key);
            if (!agg) {
                agg = {
                    bucket, first: row.observed_at, last: row.observed_at,
                    source: row.source, destination: row.destination, protocol: row.protocol,
                    sourcePort: row.source_port, destinationPort: row.destination_port,
                    packets: 0, bytes: 0, metadata: new Set<string>(),
                };
                groups.set(key, agg);
            }
            if (row.observed_at < agg.first) agg.first = row.observed_at;
            if (row.observed_at > agg.last) agg.last = row.observed_at;
            agg.packets += 1;
            agg.bytes += row.bytes;
            if (row.metadata && row.metadata !== 'No application metadata') agg.metadata.add(row.metadata);
        }

        database.exec('BEGIN IMMEDIATE');
        try {
            for (const agg of groups.values()) {
                const existing = selectFlowMetadata.get(agg.bucket, agg.source, agg.destination, agg.protocol, agg.sourcePort, agg.destinationPort) as { metadata_json: string } | undefined;
                const merged = mergeMetadata(existing?.metadata_json, Array.from(agg.metadata));
                upsertFlow.run(agg.bucket, agg.first, agg.last, agg.source, agg.destination, agg.protocol, agg.sourcePort, agg.destinationPort, agg.packets, agg.bytes, merged);
            }
            // Delete by explicit id so rows arriving mid-batch are never removed
            // without having been aggregated.
            for (let index = 0; index < ids.length; index += 500) {
                const slice = ids.slice(index, index + 500);
                database.prepare(`DELETE FROM packets WHERE id IN (${slice.map(() => '?').join(',')})`).run(...slice);
            }
            database.exec('COMMIT');
        } catch (error) {
            database.exec('ROLLBACK');
            throw error;
        }

        return { packetsIn: rows.length, flowsOut: groups.size };
    }

    function runRollup(nowMs = Date.now()): RollupResult {
        const cutoff = new Date(nowMs - PACKET_RETENTION_HOURS * 3600_000).toISOString();
        let packetsIn = 0;
        let flowsOut = 0;
        for (;;) {
            const batch = runRollupBatch(cutoff);
            if (batch.packetsIn === 0) break;
            packetsIn += batch.packetsIn;
            flowsOut += batch.flowsOut;
            if (batch.packetsIn < ROLLUP_BATCH_SIZE) break;
        }
        updateRollupState.run(new Date().toISOString(), packetsIn, flowsOut, packetsIn);
        return { packetsIn, flowsOut };
    }

    // Retention is enforced here rather than merely recorded, so the compliance report
    // can assert what actually happened instead of echoing a stored number.
    function purgeExpiredFlows(nowMs = Date.now()): number {
        const settings = selectSettings.get() as { retention_days: number; auto_purge: number } | undefined;
        if (!settings || !settings.auto_purge) return 0;
        const cutoff = new Date(nowMs - settings.retention_days * 86400_000).toISOString();
        const info = database.prepare('DELETE FROM flows WHERE last_seen < ?').run(cutoff);
        const removed = Number(info.changes || 0);
        updatePurgeState.run(new Date().toISOString(), removed);
        return removed;
    }

    return { runRollup, runRollupBatch, purgeExpiredFlows, state: () => selectState.get() };
}
