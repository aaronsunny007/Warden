#!/usr/bin/env node
/**
 * warden-policy: the trusted compiler as a command-line tool.
 * The Python validation gate shells out to this so there is one compiler, one hash
 * function and one signer.
 */
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { createInterface } from 'node:readline';
import { parseArgs } from 'node:util';
import { generateSigningKey, loadBundle, signBundle } from './bundle.js';
import { compileRule, compileRules } from './compiler.js';
import { PolicySet } from './engine.js';
import { BUNDLE_SCHEMA, jsonSchema, MODES, type Approval, type MessageContext, type Mode } from './schema.js';

const USAGE = `warden-policy <command> [options]

Commands:
  schema                                 print the Policy IR JSON Schema
  lint <file>                            compile a rule, rule array or bundle; report G1 static-check issues
  hash <file>                            print rule hashes (approvals bind to these)
  replay --rules <file> --corpus <jsonl> [--force-mode enforce] [--out <jsonl>]
                                         evaluate rules over recorded messages
  bundle --rules <file> [--approvals <file>] --id <id> --out <file> [--allow-machine-approval]
                                         assemble an unsigned bundle
  keygen --key-id <id> --out-dir <dir>   create an Ed25519 signing key pair
  sign --bundle <file> --key <pem> --key-id <id> --out <file>
  verify --bundle <file> --pub <pem> [--key-id <id>]
`;

function readJson(path: string): unknown {
  return JSON.parse(readFileSync(path, 'utf8'));
}

function rulesFrom(doc: unknown): unknown[] {
  if (Array.isArray(doc)) return doc;
  if (doc && typeof doc === 'object' && 'rules' in doc) return (doc as { rules: unknown[] }).rules;
  return [doc];
}

async function replay(
  rulesPath: string,
  corpusPath: string,
  forceMode: Mode | undefined,
  outPath?: string,
): Promise<number> {
  const { compiled, failures } = compileRules(rulesFrom(readJson(rulesPath)));
  if (failures.length) {
    console.error(JSON.stringify({ error: 'compile_failed', failures }));
    return 2;
  }
  const policy = new PolicySet(compiled);
  const rl = createInterface({
    input: corpusPath === '-' ? process.stdin : (await import('node:fs')).createReadStream(corpusPath),
    crlfDelay: Infinity,
  });
  const out: string[] = [];
  const summary = {
    messages: 0,
    fired: 0,
    byLabel: {} as Record<string, { n: number; fired: number }>,
    byRule: {} as Record<string, number>,
  };
  for await (const line of rl) {
    if (!line.trim()) continue;
    const rec = JSON.parse(line) as { id: string; ctx: MessageContext; label?: string };
    const ev = policy.evaluate(rec.ctx, forceMode ? { forceMode } : {});
    const fired = ev.enforced.length + ev.observed.length > 0;
    summary.messages++;
    if (fired) summary.fired++;
    const label = rec.label ?? 'unlabelled';
    const b = (summary.byLabel[label] ??= { n: 0, fired: 0 });
    b.n++;
    if (fired) b.fired++;
    for (const m of [...ev.enforced, ...ev.observed])
      summary.byRule[m.ruleId] = (summary.byRule[m.ruleId] ?? 0) + 1;
    out.push(
      JSON.stringify({
        id: rec.id,
        label: rec.label,
        decision: ev.decision,
        enforced: ev.enforced.map((m) => m.ruleId),
        observed: ev.observed.map((m) => m.ruleId),
      }),
    );
  }
  const body = out.join('\n') + (out.length ? '\n' : '');
  if (outPath) writeFileSync(outPath, body);
  else process.stdout.write(body);
  console.error(JSON.stringify(summary));
  return 0;
}

async function main(argv: string[]): Promise<number> {
  const [cmd, ...rest] = argv;
  const { values, positionals } = parseArgs({
    args: rest,
    allowPositionals: true,
    options: {
      rules: { type: 'string' },
      corpus: { type: 'string' },
      'force-mode': { type: 'string' },
      out: { type: 'string' },
      approvals: { type: 'string' },
      id: { type: 'string' },
      'key-id': { type: 'string' },
      'out-dir': { type: 'string' },
      bundle: { type: 'string' },
      key: { type: 'string' },
      pub: { type: 'string' },
      'allow-machine-approval': { type: 'boolean' },
    },
  });
  switch (cmd) {
    case 'schema':
      process.stdout.write(JSON.stringify(jsonSchema(), null, 2) + '\n');
      return 0;
    case 'lint': {
      const file = positionals[0];
      if (!file) throw new Error('lint needs a file');
      const results = rulesFrom(readJson(file)).map((r, index) => {
        const c = compileRule(r);
        return c.ok
          ? { index, id: c.compiled.rule.id, ok: true, hash: c.compiled.hash, warnings: c.warnings }
          : { index, id: (r as { id?: string })?.id, ok: false, errors: c.errors, warnings: c.warnings };
      });
      process.stdout.write(JSON.stringify(results, null, 2) + '\n');
      return results.every((r) => r.ok) ? 0 : 1;
    }
    case 'hash': {
      const file = positionals[0];
      if (!file) throw new Error('hash needs a file');
      const { compiled, failures } = compileRules(rulesFrom(readJson(file)));
      process.stdout.write(
        JSON.stringify(
          {
            hashes: compiled.map((c) => ({ id: c.rule.id, version: c.rule.version, hash: c.hash })),
            failures,
          },
          null,
          2,
        ) + '\n',
      );
      return failures.length ? 1 : 0;
    }
    case 'replay': {
      if (!values.rules || !values.corpus) throw new Error('replay needs --rules and --corpus');
      const fm = values['force-mode'];
      if (fm && !(MODES as readonly string[]).includes(fm))
        throw new Error(`--force-mode must be one of ${MODES.join(', ')}`);
      return replay(values.rules, values.corpus, fm as Mode | undefined, values.out);
    }
    case 'bundle': {
      if (!values.rules || !values.id || !values.out) throw new Error('bundle needs --rules, --id and --out');
      const approvals = values.approvals ? (readJson(values.approvals) as Approval[]) : [];
      const bundle = {
        schema: BUNDLE_SCHEMA,
        id: values.id,
        createdAt: new Date().toISOString(),
        rules: rulesFrom(readJson(values.rules)),
        approvals,
      };
      const check = loadBundle(bundle, {
        trustedKeys: {},
        allowUnsigned: true,
        requireHumanForEnforce: !values['allow-machine-approval'],
      });
      if (!check.ok) {
        console.error(JSON.stringify(check.errors, null, 2));
        return 1;
      }
      writeFileSync(values.out, JSON.stringify(check.loaded.bundle, null, 2) + '\n');
      return 0;
    }
    case 'keygen': {
      const keyId = values['key-id'];
      const dir = values['out-dir'];
      if (!keyId || !dir) throw new Error('keygen needs --key-id and --out-dir');
      mkdirSync(dir, { recursive: true });
      const kp = generateSigningKey(keyId);
      writeFileSync(join(dir, `${keyId}.key.pem`), kp.privateKeyPem, { mode: 0o600 });
      writeFileSync(join(dir, `${keyId}.pub.pem`), kp.publicKeyPem);
      console.log(
        JSON.stringify({
          keyId,
          private: join(dir, `${keyId}.key.pem`),
          public: join(dir, `${keyId}.pub.pem`),
        }),
      );
      return 0;
    }
    case 'sign': {
      if (!values.bundle || !values.key || !values['key-id'] || !values.out)
        throw new Error('sign needs --bundle, --key, --key-id and --out');
      const signed = signBundle(readJson(values.bundle), values['key-id'], readFileSync(values.key, 'utf8'));
      writeFileSync(values.out, JSON.stringify(signed, null, 2) + '\n');
      return 0;
    }
    case 'verify': {
      if (!values.bundle || !values.pub) throw new Error('verify needs --bundle and --pub');
      const doc = readJson(values.bundle) as { signature?: { keyId?: string } };
      const keyId = values['key-id'] ?? doc.signature?.keyId ?? 'default';
      const r = loadBundle(doc, { trustedKeys: { [keyId]: readFileSync(values.pub, 'utf8') } });
      process.stdout.write(
        JSON.stringify(
          r.ok ? { ok: true, rules: r.loaded.compiled.length } : { ok: false, errors: r.errors },
          null,
          2,
        ) + '\n',
      );
      return r.ok ? 0 : 1;
    }
    default:
      process.stderr.write(USAGE);
      return cmd ? 64 : 0;
  }
}

main(process.argv.slice(2)).then(
  (code) => {
    process.exitCode = code;
  },
  (err: unknown) => {
    console.error(`warden-policy: ${(err as Error).message}`);
    process.exitCode = 64;
  },
);
