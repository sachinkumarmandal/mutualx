import { lookup } from 'node:dns/promises';
import { isIP } from 'node:net';

/**
 * All outbound HTTP from the backend goes through `safeFetch`:
 *  - https only, exact-hostname allow-list (Meta endpoints);
 *  - resolved addresses must be public (blocks loopback, RFC1918, link-local,
 *    CGNAT, cloud metadata, multicast, IPv6 ULA / mapped addresses);
 *  - redirects are never followed;
 *  - hard timeout and response-size cap;
 *  - errors never echo the URL (which may contain credentials).
 */
export const META_ALLOWED_HOSTS = ['graph.instagram.com', 'api.instagram.com'] as const;

export class UpstreamError extends Error {
  constructor(public readonly kind: 'blocked' | 'network' | 'timeout' | 'too_large' | 'http', public readonly status?: number) {
    super(`upstream request failed: ${kind}${status ? ` (${status})` : ''}`);
    this.name = 'UpstreamError';
  }
}

export function isBlockedIp(ip: string): boolean {
  const family = isIP(ip);
  if (family === 4) {
    const parts = ip.split('.').map(Number) as [number, number, number, number];
    const [a, b] = parts;
    return (
      a === 0 ||
      a === 10 ||
      a === 127 ||
      (a === 100 && b >= 64 && b <= 127) ||
      (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      (a === 192 && b === 0) ||
      (a === 198 && (b === 18 || b === 19)) ||
      a >= 224
    );
  }
  if (family === 6) {
    const v = ip.toLowerCase();
    if (v === '::' || v === '::1') return true;
    if (v.startsWith('::ffff:')) {
      const mapped = v.slice(7);
      return isIP(mapped) === 4 ? isBlockedIp(mapped) : true;
    }
    return v.startsWith('fc') || v.startsWith('fd') || v.startsWith('fe8') || v.startsWith('fe9') || v.startsWith('fea') || v.startsWith('feb') || v.startsWith('ff');
  }
  return true; // not a valid IP literal → refuse
}

export type Resolver = (hostname: string) => Promise<string[]>;

const defaultResolver: Resolver = async (hostname) => (await lookup(hostname, { all: true })).map((r) => r.address);

export interface SafeFetchOptions {
  method?: 'GET' | 'POST';
  headers?: Record<string, string>;
  body?: URLSearchParams;
  allowHosts?: readonly string[];
  timeoutMs?: number;
  maxBytes?: number;
  resolver?: Resolver;
  fetchImpl?: typeof fetch;
}

export async function assertSafeUrl(rawUrl: string, allowHosts: readonly string[], resolver: Resolver = defaultResolver): Promise<URL> {
  let url: URL;
  try {
    url = new URL(rawUrl);
  } catch {
    throw new UpstreamError('blocked');
  }
  if (url.protocol !== 'https:') throw new UpstreamError('blocked');
  if (url.username || url.password) throw new UpstreamError('blocked');
  if (url.port && url.port !== '443') throw new UpstreamError('blocked');
  if (!allowHosts.includes(url.hostname)) throw new UpstreamError('blocked');
  if (isIP(url.hostname)) throw new UpstreamError('blocked');

  let addresses: string[];
  try {
    addresses = await resolver(url.hostname);
  } catch {
    throw new UpstreamError('network');
  }
  if (addresses.length === 0 || addresses.some(isBlockedIp)) throw new UpstreamError('blocked');
  return url;
}

export async function safeFetch(rawUrl: string, opts: SafeFetchOptions = {}): Promise<{ status: number; json: unknown }> {
  const url = await assertSafeUrl(rawUrl, opts.allowHosts ?? META_ALLOWED_HOSTS, opts.resolver);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), opts.timeoutMs ?? 8000);
  const maxBytes = opts.maxBytes ?? 256 * 1024;
  try {
    const res = await (opts.fetchImpl ?? fetch)(url, {
      method: opts.method ?? 'GET',
      headers: { accept: 'application/json', ...opts.headers },
      body: opts.body,
      redirect: 'error',
      signal: controller.signal,
      credentials: 'omit',
    });
    const declared = Number(res.headers.get('content-length') ?? 0);
    if (declared > maxBytes) throw new UpstreamError('too_large');
    const buf = new Uint8Array(await res.arrayBuffer());
    if (buf.byteLength > maxBytes) throw new UpstreamError('too_large');
    let json: unknown = null;
    try {
      json = JSON.parse(new TextDecoder().decode(buf));
    } catch {
      json = null;
    }
    return { status: res.status, json };
  } catch (err) {
    if (err instanceof UpstreamError) throw err;
    if (controller.signal.aborted) throw new UpstreamError('timeout');
    throw new UpstreamError('network');
  } finally {
    clearTimeout(timer);
  }
}
