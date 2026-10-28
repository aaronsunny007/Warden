/**
 * Text normalisation and hidden-character detection.
 *
 * Attackers hide instructions with zero-width characters, Unicode tag characters
 * (invisible "ASCII smuggling"), bidi controls and look-alike letters. Normalising
 * before matching means one rule covers these variants.
 */

export interface Span {
  start: number;
  end: number;
  text: string;
}

// Zero-width and formatting characters, bidi controls, BOM, Unicode tags block,
// and variation selectors (used to smuggle bytes after an emoji).
// Variation selectors are matched on purpose: they can smuggle bytes after a visible character.
const INVISIBLE_RE =
  // eslint-disable-next-line no-misleading-character-class
  /[\u00AD\u180E\u200B-\u200F\u202A-\u202E\u2060-\u2064\u2066-\u206F\uFEFF\uFE00-\uFE0F]|\uDB40[\uDC00-\uDC7F]|\uDB40[\uDD00-\uDDEF]/g;

/** Look-alike letters from Cyrillic and Greek folded to Latin. */
const HOMOGLYPHS: Record<string, string> = {
  а: 'a',
  е: 'e',
  о: 'o',
  р: 'p',
  с: 'c',
  у: 'y',
  х: 'x',
  і: 'i',
  ј: 'j',
  ѕ: 's',
  ԁ: 'd',
  ɡ: 'g',
  һ: 'h',
  ӏ: 'l',
  А: 'A',
  В: 'B',
  Е: 'E',
  К: 'K',
  М: 'M',
  Н: 'H',
  О: 'O',
  Р: 'P',
  С: 'C',
  Т: 'T',
  Х: 'X',
  І: 'I',
  Ј: 'J',
  Ѕ: 'S',
  α: 'a',
  ο: 'o',
  ρ: 'p',
  ν: 'v',
  τ: 't',
  ι: 'i',
  κ: 'k',
  χ: 'x',
  υ: 'u',
  Α: 'A',
  Β: 'B',
  Ε: 'E',
  Ζ: 'Z',
  Η: 'H',
  Ι: 'I',
  Κ: 'K',
  Μ: 'M',
  Ν: 'N',
  Ο: 'O',
  Ρ: 'P',
  Τ: 'T',
  Υ: 'Y',
  Χ: 'X',
};
const HOMOGLYPH_RE = new RegExp(`[${Object.keys(HOMOGLYPHS).join('')}]`, 'gu');

/** Decode Unicode tag characters (U+E0020..U+E007E) into the ASCII they smuggle. */
export function decodeTagChars(s: string): string {
  let out = '';
  for (const ch of s) {
    const cp = ch.codePointAt(0)!;
    if (cp >= 0xe0020 && cp <= 0xe007e) out += String.fromCharCode(cp - 0xe0000);
  }
  return out;
}

export function findHiddenUnicode(s: string): Span[] {
  const spans: Span[] = [];
  for (const m of s.matchAll(INVISIBLE_RE)) {
    const start = m.index ?? 0;
    const last = spans[spans.length - 1];
    if (last && last.end === start) {
      last.end = start + m[0].length;
      last.text += m[0];
    } else {
      spans.push({ start, end: start + m[0].length, text: m[0] });
    }
  }
  return spans;
}

/**
 * NFKC, reveal smuggled tag text, strip invisibles, fold homoglyphs, collapse whitespace.
 * Idempotent: normalize(normalize(x)) === normalize(x).
 */
export function normalize(s: string): string {
  const smuggled = decodeTagChars(s);
  let t = s.normalize('NFKC');
  t = t.replace(INVISIBLE_RE, '');
  t = t.replace(HOMOGLYPH_RE, (c) => HOMOGLYPHS[c] ?? c);
  if (smuggled) t = `${t} ${smuggled}`;
  t = t.replace(/\s+/g, ' ').trim();
  // A second NFKC pass keeps the function idempotent when folding produced composable sequences.
  return t.normalize('NFKC');
}

export function rot13(s: string): string {
  return s.replace(/[A-Za-z]/g, (c) => {
    const base = c <= 'Z' ? 65 : 97;
    return String.fromCharCode(((c.charCodeAt(0) - base + 13) % 26) + base);
  });
}

const B64_RE = /[A-Za-z0-9+/_-]{16,}={0,2}/g;
const HEX_RE = /\b(?:[0-9a-fA-F]{2}){8,}\b/g;

function printableRatio(s: string): number {
  if (!s) return 0;
  let ok = 0;
  for (const ch of s) {
    const c = ch.charCodeAt(0);
    if ((c >= 32 && c < 127) || c === 10 || c === 13 || c === 9) ok++;
  }
  return ok / s.length;
}

/** Decode embedded chunks so encoded instructions can be matched. Returns decoded fragments only. */
export function decodeFragments(s: string, encodings: readonly string[]): string[] {
  const out: string[] = [];
  const capped = s.slice(0, 65536);
  if (encodings.includes('base64')) {
    for (const m of capped.matchAll(B64_RE)) {
      try {
        const d = Buffer.from(m[0].replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8');
        if (d.length >= 4 && printableRatio(d) > 0.9) out.push(d);
      } catch {
        /* not base64 */
      }
    }
  }
  if (encodings.includes('hex')) {
    for (const m of capped.matchAll(HEX_RE)) {
      const d = Buffer.from(m[0], 'hex').toString('utf8');
      if (printableRatio(d) > 0.9) out.push(d);
    }
  }
  if (encodings.includes('url') && /%[0-9a-fA-F]{2}/.test(capped)) {
    try {
      out.push(decodeURIComponent(capped.replace(/\+/g, ' ')));
    } catch {
      /* malformed escape */
    }
  }
  if (encodings.includes('rot13')) out.push(rot13(capped));
  return out;
}
