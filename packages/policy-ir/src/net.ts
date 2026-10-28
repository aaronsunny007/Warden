/**
 * URL extraction and SSRF analysis.
 *
 * Uses the WHATWG URL parser, which already canonicalises decimal, hex, octal and
 * short-form IPv4 hosts (http://2130706433/ -> 127.0.0.1), so encoded addresses
 * are judged by the address they actually reach.
 */
import { isIP } from 'node:net';
import type { Span } from './text.js';

export interface FoundUrl {
  raw: string;
  url: URL | null;
  markdownImage: boolean;
  span: Span;
}

const URL_RE =
  /\b[a-zA-Z][a-zA-Z0-9+.-]{1,15}:\/\/(?:[^\s<>"'`@/]{0,256}@)?(?:\[[0-9a-fA-F:.%]{2,64}\])?[^\s<>"'`)\]}]*/g;
const MD_IMAGE_RE = /!\[[^\]]{0,200}\]\(\s*<?([^)\s>]+)>?(?:\s+"[^"]*")?\s*\)/g;
const BARE_HOST_RE =
  /(?<![@\w.-])((?:\d{1,3}\.){3}\d{1,3}|localhost|(?:[a-z0-9-]+\.)+(?:internal|local|localhost))(?::\d{1,5})?(\/[^\s"'<>]*)?/gi;

function stripTrailingPunct(s: string): string {
  return s.replace(/[.,;:!?]+$/, '');
}

export function extractUrls(text: string): FoundUrl[] {
  const capped = text.slice(0, 65536);
  const found: FoundUrl[] = [];
  const seen = new Set<string>();
  const images = new Set<string>();
  for (const m of capped.matchAll(MD_IMAGE_RE)) {
    const raw = m[1] ?? '';
    images.add(raw);
  }
  const push = (raw: string, start: number, md: boolean, length = raw.length): void => {
    const key = `${start}:${raw}`;
    if (seen.has(key)) return;
    seen.add(key);
    let url: URL | null;
    try {
      url = new URL(raw);
    } catch {
      url = null;
    }
    found.push({
      raw,
      url,
      markdownImage: md,
      span: { start, end: start + length, text: capped.slice(start, start + length) },
    });
  };
  for (const m of capped.matchAll(URL_RE)) {
    const raw = stripTrailingPunct(m[0]);
    push(raw, m.index ?? 0, images.has(raw) || images.has(m[0]));
  }
  for (const m of capped.matchAll(BARE_HOST_RE)) {
    const start = m.index ?? 0;
    // Skip hosts already covered by a scheme URL.
    if (found.some((f) => start >= f.span.start && start < f.span.end)) continue;
    const bare = stripTrailingPunct(m[0]);
    push(`http://${bare}`, start, false, bare.length);
  }
  return found;
}

function v4ToInt(ip: string): number {
  return ip.split('.').reduce((acc, o) => (acc << 8) + Number(o), 0) >>> 0;
}

const V4_PRIVATE: Array<[string, number]> = [
  ['0.0.0.0', 8],
  ['10.0.0.0', 8],
  ['100.64.0.0', 10],
  ['127.0.0.0', 8],
  ['169.254.0.0', 16],
  ['172.16.0.0', 12],
  ['192.0.0.0', 24],
  ['192.0.2.0', 24],
  ['192.168.0.0', 16],
  ['198.18.0.0', 15],
  ['198.51.100.0', 24],
  ['203.0.113.0', 24],
  ['224.0.0.0', 4],
  ['240.0.0.0', 4],
];

export function isPrivateV4(ip: string): boolean {
  const n = v4ToInt(ip);
  return V4_PRIVATE.some(([base, bits]) => {
    const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
    return (n & mask) === (v4ToInt(base) & mask);
  });
}

function expandV6(ip: string): number[] | null {
  let s = ip.toLowerCase();
  const zone = s.indexOf('%');
  if (zone >= 0) s = s.slice(0, zone);
  // Embedded dotted IPv4 tail.
  const v4tail = s.match(/(\d{1,3}(?:\.\d{1,3}){3})$/);
  if (v4tail) {
    const n = v4ToInt(v4tail[1]!);
    s = s.slice(0, -v4tail[1]!.length) + `${(n >>> 16).toString(16)}:${(n & 0xffff).toString(16)}`;
  }
  const halves = s.split('::');
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(':') : [];
  const tail = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  const fill = halves.length === 2 ? 8 - head.length - tail.length : 0;
  const parts = [...head, ...Array<string>(Math.max(fill, 0)).fill('0'), ...tail];
  if (parts.length !== 8) return null;
  return parts.map((p) => parseInt(p || '0', 16));
}

export function isPrivateV6(ip: string): boolean {
  const p = expandV6(ip);
  if (!p) return true; // unparsable: treat as unsafe
  const [a, b, c, d, e, f, g, h] = p as [number, number, number, number, number, number, number, number];
  const allZeroPrefix = a === 0 && b === 0 && c === 0 && d === 0 && e === 0;
  if (allZeroPrefix && f === 0 && g === 0 && (h === 0 || h === 1)) return true; // :: and ::1
  if (allZeroPrefix && f === 0xffff) return isPrivateV4(`${g >> 8}.${g & 255}.${h >> 8}.${h & 255}`); // v4-mapped
  if (a === 0x64 && b === 0xff9b) return isPrivateV4(`${g >> 8}.${g & 255}.${h >> 8}.${h & 255}`); // NAT64
  if ((a & 0xfe00) === 0xfc00) return true; // unique local fc00::/7 (includes AWS fd00:ec2::254)
  if ((a & 0xffc0) === 0xfe80) return true; // link-local
  if ((a & 0xff00) === 0xff00) return true; // multicast
  if (a === 0x2001 && b === 0x0db8) return true; // documentation
  return false;
}

const INTERNAL_HOSTS = new Set([
  'localhost',
  'metadata',
  'metadata.google.internal',
  'instance-data',
  'instance-data.ec2.internal',
  'kubernetes.default',
  'kubernetes.default.svc',
]);
const INTERNAL_SUFFIXES = [
  '.localhost',
  '.internal',
  '.local',
  '.svc',
  '.cluster.local',
  '.home.arpa',
  '.lan',
];
// Wildcard DNS services that resolve an embedded IP: 127.0.0.1.nip.io, 10-0-0-1.sslip.io
const WILDCARD_DNS =
  /(?:^|\.)((?:\d{1,3}[.-]){3}\d{1,3})\.(?:nip\.io|sslip\.io|xip\.io|traefik\.me|localtest\.me)$/;

/** True when the host is loopback, private, link-local, cloud metadata or otherwise internal. */
export function isPrivateHost(hostname: string): boolean {
  let h = hostname.toLowerCase().replace(/\.$/, '');
  if (h.startsWith('[') && h.endsWith(']')) h = h.slice(1, -1);
  if (!h) return true;
  const kind = isIP(h);
  if (kind === 4) return isPrivateV4(h);
  if (kind === 6) return isPrivateV6(h);
  if (INTERNAL_HOSTS.has(h)) return true;
  if (INTERNAL_SUFFIXES.some((s) => h.endsWith(s))) return true;
  if (h === 'localtest.me' || h.endsWith('.localtest.me')) return true;
  const wild = h.match(WILDCARD_DNS);
  if (wild) return isPrivateV4(wild[1]!.replace(/-/g, '.'));
  return false;
}

export function hostMatches(hostname: string, pattern: string): boolean {
  const h = hostname.toLowerCase().replace(/\.$/, '');
  const p = pattern.toLowerCase();
  if (p.startsWith('*.')) {
    const suffix = p.slice(1);
    return h.endsWith(suffix) || h === p.slice(2);
  }
  return h === p;
}

const EMAIL_RE = /[A-Za-z0-9._%+-]{1,64}@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)/g;

export function extractEmails(text: string): Array<{ address: string; domain: string; span: Span }> {
  const out: Array<{ address: string; domain: string; span: Span }> = [];
  for (const m of text.slice(0, 65536).matchAll(EMAIL_RE)) {
    const start = m.index ?? 0;
    out.push({
      address: m[0],
      domain: (m[1] ?? '').toLowerCase(),
      span: { start, end: start + m[0].length, text: m[0] },
    });
  }
  return out;
}
