import { describe, expect, it } from 'vitest';
import { extractEmails, extractUrls, hostMatches, isPrivateHost } from '../src/index.js';

describe('isPrivateHost', () => {
  it.each([
    '127.0.0.1',
    'localhost',
    'LOCALHOST.',
    '10.1.2.3',
    '172.20.0.1',
    '192.168.1.1',
    '169.254.169.254',
    '100.64.0.1',
    '0.0.0.0',
    '[::1]',
    '::',
    '[::ffff:127.0.0.1]',
    '::ffff:7f00:1',
    'fd00:ec2::254',
    'fe80::1',
    '64:ff9b::a9fe:a9fe',
    'metadata.google.internal',
    'instance-data',
    'db.internal',
    'printer.local',
    '127.0.0.1.nip.io',
    '10-0-0-1.sslip.io',
    'kubernetes.default.svc',
  ])('flags %s', (h) => expect(isPrivateHost(h)).toBe(true));

  it.each(['example.com', '8.8.8.8', '1.1.1.1', 'api.github.com', '2606:4700::1111', '172.32.0.1', 'nip.io'])(
    'allows %s',
    (h) => expect(isPrivateHost(h)).toBe(false),
  );
});

describe('extractUrls', () => {
  it('canonicalises encoded IPv4 hosts via the WHATWG parser', () => {
    const hosts = extractUrls(
      'see http://2130706433/x and http://0x7f000001/ and http://0177.0.0.1/ and http://127.1/',
    ).map((u) => u.url?.hostname);
    expect(hosts).toEqual(['127.0.0.1', '127.0.0.1', '127.0.0.1', '127.0.0.1']);
    expect(hosts.every((h) => isPrivateHost(h!))).toBe(true);
  });

  it('finds markdown images and marks them', () => {
    const urls = extractUrls('Done! ![logo](https://evil.example/p.png?d=SECRET) and https://ok.example/');
    expect(urls.find((u) => u.raw.startsWith('https://evil'))?.markdownImage).toBe(true);
    expect(urls.find((u) => u.raw.startsWith('https://ok'))?.markdownImage).toBe(false);
  });

  it('finds bare internal hosts', () => {
    const urls = extractUrls('fetch metadata.google.internal/computeMetadata/v1 then 169.254.169.254/latest');
    expect(urls.map((u) => u.url?.hostname)).toEqual(['metadata.google.internal', '169.254.169.254']);
  });

  it('strips trailing punctuation', () => {
    expect(extractUrls('Go to https://example.com/a.').map((u) => u.raw)).toEqual(['https://example.com/a']);
  });
});

describe('hostMatches and emails', () => {
  it('matches wildcard suffixes', () => {
    expect(hostMatches('mail.acme.example', '*.acme.example')).toBe(true);
    expect(hostMatches('acme.example', '*.acme.example')).toBe(true);
    expect(hostMatches('evilacme.example', '*.acme.example')).toBe(false);
  });
  it('extracts email domains', () => {
    expect(extractEmails('cc: Bob <bob@Evil.Example>, alice@acme.example').map((e) => e.domain)).toEqual([
      'evil.example',
      'acme.example',
    ]);
  });
});
