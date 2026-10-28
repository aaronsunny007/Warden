/** Prometheus metrics. The canary stage's rollback alarms read these. */
import { Counter, Gauge, Histogram, Registry, collectDefaultMetrics } from 'prom-client';

export class Metrics {
  readonly registry = new Registry();
  readonly overhead: Histogram<'channel' | 'layer'>;
  readonly upstream: Histogram<'server'>;
  readonly verdicts: Counter<'channel' | 'decision' | 'risk_tier'>;
  readonly ruleHits: Counter<'rule_id' | 'mode'>;
  readonly detectorFailures: Counter<'channel'>;
  readonly taintedSessions: Counter;
  readonly toolStatus: Gauge<'status'>;
  readonly upstreamUp: Gauge<'server'>;

  constructor() {
    collectDefaultMetrics({ register: this.registry, prefix: 'warden_' });
    const buckets = [0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5];
    this.overhead = new Histogram({
      name: 'warden_overhead_seconds',
      help: 'Time Warden adds per inspected message',
      labelNames: ['channel', 'layer'],
      buckets,
      registers: [this.registry],
    });
    this.upstream = new Histogram({
      name: 'warden_upstream_seconds',
      help: 'Upstream tool call latency',
      labelNames: ['server'],
      buckets,
      registers: [this.registry],
    });
    this.verdicts = new Counter({
      name: 'warden_verdicts_total',
      help: 'Verdicts by channel and decision',
      labelNames: ['channel', 'decision', 'risk_tier'],
      registers: [this.registry],
    });
    this.ruleHits = new Counter({
      name: 'warden_rule_hits_total',
      help: 'Rule matches by mode',
      labelNames: ['rule_id', 'mode'],
      registers: [this.registry],
    });
    this.detectorFailures = new Counter({
      name: 'warden_detector_unavailable_total',
      help: 'Detection calls that failed or timed out',
      labelNames: ['channel'],
      registers: [this.registry],
    });
    this.taintedSessions = new Counter({
      name: 'warden_sessions_tainted_total',
      help: 'Sessions tainted by untrusted content',
      registers: [this.registry],
    });
    this.toolStatus = new Gauge({
      name: 'warden_tools',
      help: 'Tools by pin status',
      labelNames: ['status'],
      registers: [this.registry],
    });
    this.upstreamUp = new Gauge({
      name: 'warden_upstream_up',
      help: 'Upstream MCP server connected',
      labelNames: ['server'],
      registers: [this.registry],
    });
  }
}
