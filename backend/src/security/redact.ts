/**
 * Secret redaction used by the logger, the audit trail and error handling so
 * credentials can never be written to logs or returned to clients.
 */
const SECRET_KEY = /(secret|token|password|passwd|authorization|cookie|code|signature|signed_request|key)/i;
const BEARER = /Bearer\s+[A-Za-z0-9._~+/=-]+/gi;
const QUERY_SECRET = /([?&](?:access_token|client_secret|code|state|signed_request)=)[^&\s]+/gi;
const LONG_TOKEN = /\b[A-Za-z0-9_-]{40,}\b/g;

export const REDACTED = '[REDACTED]';

export function redactString(input: string): string {
  return input.replace(BEARER, `Bearer ${REDACTED}`).replace(QUERY_SECRET, `$1${REDACTED}`).replace(LONG_TOKEN, REDACTED);
}

export function redactValue(value: unknown, depth = 0): unknown {
  if (typeof value === 'string') return redactString(value);
  if (depth > 4 || value === null || typeof value !== 'object') return value;
  if (Array.isArray(value)) return value.map((v) => redactValue(v, depth + 1));
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
    out[k] = SECRET_KEY.test(k) ? REDACTED : redactValue(v, depth + 1);
  }
  return out;
}

/** Pino redact paths for the request shapes we log. */
export const PINO_REDACT_PATHS = [
  'req.headers.authorization',
  'req.headers.cookie',
  'res.headers["set-cookie"]',
  '*.access_token',
  '*.client_secret',
  '*.token',
  '*.code',
];
