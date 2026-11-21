import { createCipheriv, createDecipheriv, createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import type { EncryptionKey } from '../config.js';

export function randomToken(bytes = 32): string {
  return randomBytes(bytes).toString('base64url');
}

export function sha256Hex(value: string): string {
  return createHash('sha256').update(value).digest('hex');
}

export function hmacBase64Url(secret: string | Buffer, data: string): string {
  return createHmac('sha256', secret).update(data).digest('base64url');
}

/** Constant-time string comparison that tolerates different lengths. */
export function safeEqual(a: string, b: string): boolean {
  const ab = createHash('sha256').update(a).digest();
  const bb = createHash('sha256').update(b).digest();
  return timingSafeEqual(ab, bb) && a.length === b.length;
}

/**
 * AES-256-GCM envelope: `keyId.iv.tag.ciphertext` (base64url).
 * `aad` binds the ciphertext to a context (e.g. the owning user id) so that a
 * stolen ciphertext cannot be replayed onto another record.
 */
export function encrypt(plaintext: string, keys: EncryptionKey[], aad: string): string {
  const current = keys[0];
  if (!current) throw new Error('no encryption key configured');
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', current.key, iv);
  cipher.setAAD(Buffer.from(aad));
  const ct = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return [current.id, iv.toString('base64url'), tag.toString('base64url'), ct.toString('base64url')].join('.');
}

export function decrypt(payload: string, keys: EncryptionKey[], aad: string): string {
  const [keyId, iv, tag, ct, ...extra] = payload.split('.');
  if (!keyId || !iv || !tag || !ct || extra.length) throw new Error('malformed ciphertext');
  const key = keys.find((k) => k.id === keyId);
  if (!key) throw new Error('unknown key id');
  const decipher = createDecipheriv('aes-256-gcm', key.key, Buffer.from(iv, 'base64url'));
  decipher.setAAD(Buffer.from(aad));
  decipher.setAuthTag(Buffer.from(tag, 'base64url'));
  return Buffer.concat([decipher.update(Buffer.from(ct, 'base64url')), decipher.final()]).toString('utf8');
}

/** True when the payload was encrypted with a non-current key and should be re-encrypted. */
export function needsReencryption(payload: string, keys: EncryptionKey[]): boolean {
  return payload.split('.')[0] !== keys[0]?.id;
}
