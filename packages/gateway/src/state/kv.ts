/**
 * A tiny key-value abstraction over Redis/Valkey or process memory, so taint state,
 * pins, approvals and the verdict cache work the same in tests and in production.
 */
import { Redis } from 'ioredis';

export interface KV {
  get(key: string): Promise<string | null>;
  set(key: string, value: string, ttlSeconds?: number): Promise<void>;
  del(key: string): Promise<void>;
  keys(prefix: string): Promise<string[]>;
  close(): Promise<void>;
}

export class MemoryKV implements KV {
  private data = new Map<string, { v: string; exp: number }>();

  async get(key: string): Promise<string | null> {
    const e = this.data.get(key);
    if (!e) return null;
    if (e.exp && e.exp < Date.now()) {
      this.data.delete(key);
      return null;
    }
    return e.v;
  }
  async set(key: string, value: string, ttlSeconds?: number): Promise<void> {
    this.data.set(key, { v: value, exp: ttlSeconds ? Date.now() + ttlSeconds * 1000 : 0 });
  }
  async del(key: string): Promise<void> {
    this.data.delete(key);
  }
  async keys(prefix: string): Promise<string[]> {
    const out: string[] = [];
    for (const k of this.data.keys()) if (k.startsWith(prefix) && (await this.get(k)) !== null) out.push(k);
    return out;
  }
  async close(): Promise<void> {
    this.data.clear();
  }
}

export class RedisKV implements KV {
  private client: Redis;

  constructor(url: string) {
    this.client = new Redis(url, { lazyConnect: false, maxRetriesPerRequest: 2, enableOfflineQueue: true });
  }
  async get(key: string): Promise<string | null> {
    return this.client.get(key);
  }
  async set(key: string, value: string, ttlSeconds?: number): Promise<void> {
    if (ttlSeconds) await this.client.set(key, value, 'EX', ttlSeconds);
    else await this.client.set(key, value);
  }
  async del(key: string): Promise<void> {
    await this.client.del(key);
  }
  async keys(prefix: string): Promise<string[]> {
    const out: string[] = [];
    let cursor = '0';
    do {
      const [next, batch] = await this.client.scan(cursor, 'MATCH', `${prefix}*`, 'COUNT', 500);
      cursor = next;
      out.push(...batch);
    } while (cursor !== '0');
    return out;
  }
  async close(): Promise<void> {
    await this.client.quit();
  }
}

export function createKV(redisUrl: string): KV {
  return redisUrl ? new RedisKV(redisUrl) : new MemoryKV();
}

/** Memory KV persisted to a JSON file on every write. For single-node pins without Redis. */
export class FileKV extends MemoryKV {
  private readonly path: string;
  private writing: Promise<void> = Promise.resolve();

  constructor(path: string) {
    super();
    this.path = path;
  }

  static async open(path: string): Promise<FileKV> {
    const kv = new FileKV(path);
    const { readFile } = await import('node:fs/promises');
    try {
      const data = JSON.parse(await readFile(path, 'utf8')) as Record<string, string>;
      for (const [k, v] of Object.entries(data)) await MemoryKV.prototype.set.call(kv, k, v);
    } catch {
      /* first run */
    }
    return kv;
  }

  private async flush(): Promise<void> {
    const { mkdir, writeFile, rename } = await import('node:fs/promises');
    const { dirname } = await import('node:path');
    const snapshot: Record<string, string> = {};
    for (const k of await this.keys('')) {
      const v = await this.get(k);
      if (v !== null) snapshot[k] = v;
    }
    await mkdir(dirname(this.path), { recursive: true });
    const tmp = `${this.path}.tmp`;
    await writeFile(tmp, JSON.stringify(snapshot, null, 2));
    await rename(tmp, this.path);
  }

  override async set(key: string, value: string, ttlSeconds?: number): Promise<void> {
    await super.set(key, value, ttlSeconds);
    this.writing = this.writing.then(() => this.flush());
    await this.writing;
  }

  override async del(key: string): Promise<void> {
    await super.del(key);
    this.writing = this.writing.then(() => this.flush());
    await this.writing;
  }
}
