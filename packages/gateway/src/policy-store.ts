/**
 * Loads the signed policy bundle and hot-reloads it when the file changes.
 * A bundle that fails verification is rejected and the last good bundle stays in force.
 */
import { readFileSync, watch, type FSWatcher } from 'node:fs';
import { emptyBundle, loadBundle, PolicySet, type CompileIssue, type LoadedBundle } from '@warden/policy-ir';
import type { EventBus } from './events/bus.js';

export interface PolicyStoreOptions {
  path: string;
  trustedKeys: Record<string, string>;
  allowUnsigned: boolean;
  requireHumanApproval?: boolean;
  watch: boolean;
}

export class PolicyStore {
  private current: LoadedBundle;
  private watcher: FSWatcher | null = null;
  private debounce: NodeJS.Timeout | null = null;
  lastError: CompileIssue[] = [];
  loadedAt = new Date().toISOString();

  constructor(
    private opts: PolicyStoreOptions,
    private bus: EventBus,
  ) {
    const empty = emptyBundle('none');
    this.current = { bundle: empty, compiled: [], policy: new PolicySet([]) };
    if (opts.path) {
      const res = this.reload();
      if (!res.ok)
        throw new Error(
          `policy bundle ${opts.path} rejected: ${res.errors.map((e) => `${e.path}: ${e.message}`).join('; ')}`,
        );
      if (opts.watch) this.startWatching();
    }
  }

  get policy(): PolicySet {
    return this.current.policy;
  }

  get bundle(): LoadedBundle {
    return this.current;
  }

  reload(): { ok: true } | { ok: false; errors: CompileIssue[] } {
    let doc: unknown;
    try {
      doc = JSON.parse(readFileSync(this.opts.path, 'utf8'));
    } catch (e) {
      this.lastError = [{ path: this.opts.path, message: (e as Error).message }];
      return { ok: false, errors: this.lastError };
    }
    return this.install(doc);
  }

  /** Verify and install a bundle. Used by file reload and by the admin API. */
  install(doc: unknown): { ok: true } | { ok: false; errors: CompileIssue[] } {
    const res = loadBundle(doc, {
      trustedKeys: this.opts.trustedKeys,
      allowUnsigned: this.opts.allowUnsigned,
      requireHumanForEnforce: this.opts.requireHumanApproval ?? true,
    });
    if (!res.ok) {
      this.lastError = res.errors;
      this.bus.emit('policy', { event: 'rejected', errors: res.errors });
      return { ok: false, errors: res.errors };
    }
    this.current = res.loaded;
    this.lastError = [];
    this.loadedAt = new Date().toISOString();
    this.bus.emit('policy', {
      event: 'installed',
      bundleId: res.loaded.bundle.id,
      rules: res.loaded.compiled.map((c) => ({ id: c.rule.id, version: c.rule.version, mode: c.rule.mode })),
    });
    return { ok: true };
  }

  private startWatching(): void {
    try {
      this.watcher = watch(this.opts.path, () => {
        if (this.debounce) clearTimeout(this.debounce);
        this.debounce = setTimeout(() => this.reload(), 150);
      });
    } catch {
      this.watcher = null;
    }
  }

  close(): void {
    this.watcher?.close();
    if (this.debounce) clearTimeout(this.debounce);
  }
}
