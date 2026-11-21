import { randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { decrypt, encrypt, needsReencryption, safeEqual } from '../src/security/crypto.js';
import { redactString, redactValue } from '../src/security/redact.js';
import { inspectValue, UnsafeInputError } from '../src/security/sanitize.js';
import { assertSafeUrl, isBlockedIp, safeFetch, META_ALLOWED_HOSTS } from '../src/security/ssrf.js';
import { verifySignedRequest } from '../src/auth/meta.js';
import { hmacBase64Url } from '../src/security/crypto.js';

const keys = [{ id: 'k2', key: randomBytes(32) }, { id: 'k1', key: randomBytes(32) }];

describe('crypto', () => {
  it('round-trips and binds to context', () => {
    const ct = encrypt('token', keys, 'user:1');
    expect(decrypt(ct, keys, 'user:1')).toBe('token');
    expect(() => decrypt(ct, keys, 'user:2')).toThrow();
  });
  it('detects tampering and supports key rotation', () => {
    const old = encrypt('token', [keys[1]!], 'a');
    expect(needsReencryption(old, keys)).toBe(true);
    expect(decrypt(old, keys, 'a')).toBe('token');
    const ct = encrypt('token', keys, 'a');
    const parts = ct.split('.');
    parts[3] = Buffer.from('forged-bytes').toString('base64url');
    expect(() => decrypt(parts.join('.'), keys, 'a')).toThrow();
  });
  it('safeEqual compares correctly', () => {
    expect(safeEqual('abc', 'abc')).toBe(true);
    expect(safeEqual('abc', 'abd')).toBe(false);
    expect(safeEqual('abc', 'abcd')).toBe(false);
  });
});

describe('input sanitiser', () => {
  const bad = (v: unknown) => expect(() => inspectValue(v)).toThrow(UnsafeInputError);
  it('blocks NoSQL operators, prototype pollution and credentials', () => {
    bad({ $ne: null });
    bad({ a: { $gt: '' } });
    bad(JSON.parse('{"__proto__":{"x":1}}'));
    bad({ 'a.b': 1 });
    bad({ password: 'x' });
    bad({ Instagram_Password: 'x' });
    bad({ 'state[$ne]': 'x' });
  });
  it('blocks null bytes, oversize and deep payloads', () => {
    bad({ a: 'x\u0000y' });
    bad({ a: 'x'.repeat(3000) });
    bad({ a: { b: { c: { d: { e: { f: { g: 1 } } } } } } });
  });
  it('accepts normal payloads', () => {
    expect(() => inspectValue({ code: 'abc', n: [1, 2], nested: { ok: true } })).not.toThrow();
  });
});

describe('SSRF guard', () => {
  const pub = async () => ['93.184.216.34'];
  it('blocks non-https, foreign hosts, literals, ports and credentials', async () => {
    for (const u of ['http://graph.instagram.com/x', 'https://evil.example/', 'https://169.254.169.254/', 'https://[::1]/', 'https://graph.instagram.com:8443/', 'https://a:b@graph.instagram.com/']) {
      await expect(assertSafeUrl(u, META_ALLOWED_HOSTS, pub)).rejects.toThrow();
    }
  });
  it('blocks allow-listed hosts that resolve to private addresses', async () => {
    await expect(assertSafeUrl('https://graph.instagram.com/x', META_ALLOWED_HOSTS, async () => ['10.0.0.1'])).rejects.toThrow();
    await expect(assertSafeUrl('https://graph.instagram.com/x', META_ALLOWED_HOSTS, async () => ['93.184.216.34', '127.0.0.1'])).rejects.toThrow();
  });
  it('classifies IP ranges', () => {
    for (const ip of ['127.0.0.1', '10.0.0.1', '172.31.255.255', '192.168.0.1', '169.254.169.254', '100.64.0.1', '0.0.0.0', '224.0.0.1', '::1', 'fc00::1', 'fe80::1', '::ffff:10.0.0.1']) expect(isBlockedIp(ip)).toBe(true);
    for (const ip of ['8.8.8.8', '93.184.216.34', '172.32.0.1', '2606:4700:4700::1111']) expect(isBlockedIp(ip)).toBe(false);
  });
  it('does not leak the URL in errors and caps response size', async () => {
    const big: typeof fetch = async () => new Response('x'.repeat(2000), { status: 200 });
    await expect(safeFetch('https://graph.instagram.com/me?access_token=SECRETSECRET', { resolver: pub, fetchImpl: big, maxBytes: 100 })).rejects.toMatchObject({ kind: 'too_large' });
    try {
      await safeFetch('https://evil.example/?access_token=SECRETSECRET', { resolver: pub });
    } catch (e) {
      expect(String((e as Error).message)).not.toContain('SECRETSECRET');
    }
  });
});

describe('redaction', () => {
  it('removes secrets from strings and objects', () => {
    expect(redactString('https://x/?access_token=abc123&state=s')).not.toContain('abc123');
    expect(redactString('Authorization: Bearer abc.def.ghi')).not.toContain('abc.def.ghi');
    const out = JSON.stringify(redactValue({ client_secret: 'zzz', headers: { cookie: 'sid=1' }, ok: 'fine' }));
    expect(out).not.toContain('zzz');
    expect(out).not.toContain('sid=1');
    expect(out).toContain('fine');
  });
});

describe('Meta signed_request', () => {
  const secret = 'app-secret-for-tests-0123456789';
  const make = (payload: object, s = secret) => {
    const p = Buffer.from(JSON.stringify(payload)).toString('base64url');
    return `${hmacBase64Url(s, p)}.${p}`;
  };
  it('accepts a valid signature and rejects forgeries', () => {
    expect(verifySignedRequest(make({ user_id: '123', algorithm: 'HMAC-SHA256' }), secret)).toEqual({ userId: '123' });
    expect(verifySignedRequest(make({ user_id: '123' }, 'other-secret-other-secret-other'), secret)).toBeNull();
    expect(verifySignedRequest('garbage', secret)).toBeNull();
    expect(verifySignedRequest(make({ nothing: true }), secret)).toBeNull();
  });
});
