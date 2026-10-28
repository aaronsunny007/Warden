/** Every verdict is an event: the audit log, the dashboard and the learning loop consume it. */
import { appendFile, mkdir } from 'node:fs/promises';
import { dirname } from 'node:path';
import type { Verdict, WardenEvent } from './types.js';

export interface EventSink {
  name: string;
  publish(events: WardenEvent[]): Promise<void>;
  close(): Promise<void>;
}

type Listener = (e: WardenEvent) => void;

export class EventBus {
  private ring: WardenEvent[] = [];
  private listeners = new Set<Listener>();
  private queue: WardenEvent[] = [];
  private timer: NodeJS.Timeout | null = null;
  private flushing: Promise<void> = Promise.resolve();
  readonly errors: Record<string, number> = {};

  constructor(
    private sinks: EventSink[],
    private ringSize: number,
    private flushMs = 200,
  ) {}

  emit(type: WardenEvent['type'], data: unknown): void {
    const e: WardenEvent = { type, ts: new Date().toISOString(), data };
    this.ring.push(e);
    if (this.ring.length > this.ringSize) this.ring.splice(0, this.ring.length - this.ringSize);
    for (const l of this.listeners) {
      try {
        l(e);
      } catch {
        /* a slow dashboard must never break enforcement */
      }
    }
    if (this.sinks.length) {
      this.queue.push(e);
      this.timer ??= setTimeout(() => void this.flush(), this.flushMs);
    }
  }

  verdict(v: Verdict): void {
    this.emit('verdict', v);
  }

  recent(type?: WardenEvent['type'], limit = 200): WardenEvent[] {
    const items = type ? this.ring.filter((e) => e.type === type) : this.ring;
    return items.slice(-limit).reverse();
  }

  subscribe(l: Listener): () => void {
    this.listeners.add(l);
    return () => this.listeners.delete(l);
  }

  async flush(): Promise<void> {
    if (this.timer) clearTimeout(this.timer);
    this.timer = null;
    const batch = this.queue.splice(0);
    if (!batch.length) return this.flushing;
    this.flushing = this.flushing.then(async () => {
      await Promise.all(
        this.sinks.map(async (s) => {
          try {
            await s.publish(batch);
          } catch {
            this.errors[s.name] = (this.errors[s.name] ?? 0) + 1;
          }
        }),
      );
    });
    return this.flushing;
  }

  async close(): Promise<void> {
    await this.flush();
    await Promise.all(this.sinks.map((s) => s.close().catch(() => undefined)));
  }
}

export class JsonlSink implements EventSink {
  name = 'jsonl';
  private ready: Promise<unknown>;
  constructor(private path: string) {
    this.ready = mkdir(dirname(path), { recursive: true });
  }
  async publish(events: WardenEvent[]): Promise<void> {
    await this.ready;
    await appendFile(this.path, events.map((e) => JSON.stringify(e)).join('\n') + '\n');
  }
  async close(): Promise<void> {}
}
