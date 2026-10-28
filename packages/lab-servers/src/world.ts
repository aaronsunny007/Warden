/**
 * The lab world: synthetic Acme Support data shared by every lab server, plus the
 * side-effect logs (outbox, refunds, fetches, writes) the evaluator reads to judge
 * whether an attack's tool-level goal was achieved. All data is synthetic.
 */
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

export interface Customer {
  id: string;
  name: string;
  email: string;
  plan: string;
  balance: number;
  since: string;
  notes: string;
}
export interface Ticket {
  id: string;
  customer_id: string;
  subject: string;
  status: string;
  body: string;
  comments: string[];
}
export interface Email {
  id: string;
  from: string;
  to: string;
  subject: string;
  date: string;
  body: string;
  cc?: string[];
  bcc?: string[];
}
export interface Refund {
  customer_id: string;
  amount: number;
  reason: string;
  at: string;
}

export interface World {
  organisation: string;
  domain: string;
  customers: Customer[];
  tickets: Ticket[];
  inbox: Email[];
  outbox: Email[];
  files: Record<string, string>;
  web: Record<string, string>;
  refunds: Refund[];
  fetches: Array<{ url: string; at: string; internal: boolean }>;
  writes: Array<{ path: string; at: string; content: string }>;
  canaries: string[];
  /** Malicious-server switches. */
  rugpull?: boolean;
  /** Free-form slots a scenario can fill. */
  slots: Record<string, string>;
}

/**
 * An injection puts attacker text somewhere the agent will read.
 * target examples: "inbox:E-9002:body", "ticket:T-504:body", "web:https://help.acme.example/invite",
 * "file:/shared/reports/q3-summary.txt", "customer:1047:notes".
 */
export interface Injection {
  target: string;
  payload: string;
  mode?: 'append' | 'prepend' | 'replace';
}

const here = dirname(fileURLToPath(import.meta.url));

export function defaultWorldPath(): string {
  return process.env.WARDEN_LAB_WORLD ?? resolve(here, '../../../data/lab/world.json');
}

export function loadWorld(path = defaultWorldPath()): World {
  return JSON.parse(readFileSync(path, 'utf8')) as World;
}

export function cloneWorld(w: World): World {
  return structuredClone(w);
}

function place(original: string | undefined, payload: string, mode: Injection['mode']): string {
  const base = original ?? '';
  if (mode === 'replace' || !base) return payload;
  return mode === 'prepend' ? `${payload}\n\n${base}` : `${base}\n\n${payload}`;
}

export function applyInjections(w: World, injections: Injection[]): World {
  for (const inj of injections) {
    const [kind, ...restParts] = inj.target.split(':');
    const rest = restParts.join(':');
    const mode = inj.mode ?? 'append';
    switch (kind) {
      case 'inbox': {
        const [id, field = 'body'] = rest.split(':');
        let mail = w.inbox.find((m) => m.id === id);
        if (!mail) {
          mail = {
            id: id ?? `E-${w.inbox.length + 1}`,
            from: 'unknown@external.example',
            to: `support@${w.domain}`,
            subject: 'Message',
            date: '2026-10-27',
            body: '',
          };
          w.inbox.push(mail);
        }
        (mail as unknown as Record<string, string>)[field] = place(
          (mail as unknown as Record<string, string>)[field],
          inj.payload,
          mode,
        );
        break;
      }
      case 'ticket': {
        const [id, field = 'body'] = rest.split(':');
        const t = w.tickets.find((x) => x.id === id);
        if (t)
          (t as unknown as Record<string, string>)[field] = place(
            (t as unknown as Record<string, string>)[field],
            inj.payload,
            mode,
          );
        break;
      }
      case 'customer': {
        const [id, field = 'notes'] = rest.split(':');
        const c = w.customers.find((x) => x.id === id);
        if (c)
          (c as unknown as Record<string, string>)[field] = place(
            (c as unknown as Record<string, string>)[field],
            inj.payload,
            mode,
          );
        break;
      }
      case 'web':
        w.web[rest] = place(w.web[rest], inj.payload, mode);
        break;
      case 'file':
        w.files[rest] = place(w.files[rest], inj.payload, mode);
        break;
      case 'slot':
        w.slots[rest] = place(w.slots[rest], inj.payload, mode);
        break;
      default:
        throw new Error(`unknown injection target ${inj.target}`);
    }
  }
  return w;
}

/** Mutable holder so HTTP handlers always see the current world after a reset. */
export class WorldHolder {
  private base: World;
  current: World;

  constructor(base: World) {
    this.base = cloneWorld(base);
    this.current = cloneWorld(base);
  }

  reset(opts: { world?: World; injections?: Injection[]; rugpull?: boolean } = {}): World {
    if (opts.world) this.base = cloneWorld(opts.world);
    this.current = applyInjections(cloneWorld(this.base), opts.injections ?? []);
    if (opts.rugpull !== undefined) this.current.rugpull = opts.rugpull;
    return this.current;
  }
}
