/**
 * Direct Postgres audit sink, for deployments without Kafka. With Kafka, the Python
 * audit consumer writes the same table. Schema is owned by the Alembic migrations.
 */
import pg from 'pg';
import type { EventSink } from './bus.js';
import type { Verdict, WardenEvent } from './types.js';

export class PostgresSink implements EventSink {
  name = 'postgres';
  private pool: pg.Pool;

  constructor(url: string) {
    this.pool = new pg.Pool({ connectionString: url, max: 4 });
  }

  async publish(events: WardenEvent[]): Promise<void> {
    const verdicts = events.filter((e) => e.type === 'verdict').map((e) => e.data as Verdict);
    if (!verdicts.length) return;
    const cols = [
      'id',
      'ts',
      'session_id',
      'server',
      'tool',
      'channel',
      'risk_tier',
      'decision',
      'rule_ids',
      'shadow_rule_ids',
      'layer',
      'score',
      'tainted',
      'latency_ms',
      'explanation',
      'owasp',
      'bundle_id',
      'payload',
    ];
    const values: unknown[] = [];
    const rows = verdicts.map((v, i) => {
      values.push(
        v.id,
        v.ts,
        v.sessionId,
        v.server,
        v.tool,
        v.channel,
        v.riskTier,
        v.decision,
        v.ruleIds,
        v.shadowRuleIds,
        v.layer,
        v.score,
        v.tainted,
        v.latencyMs,
        v.explanation,
        v.owasp,
        v.bundleId,
        JSON.stringify(v),
      );
      return `(${cols.map((_, j) => `$${i * cols.length + j + 1}`).join(',')})`;
    });
    await this.pool.query(
      `INSERT INTO verdicts (${cols.join(',')}) VALUES ${rows.join(',')} ON CONFLICT (id) DO NOTHING`,
      values,
    );
  }

  async close(): Promise<void> {
    await this.pool.end();
  }
}
