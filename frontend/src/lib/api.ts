const BASE = (import.meta.env.VITE_API_URL ?? 'http://localhost:8080').replace(/\/$/, '');

export class ApiError extends Error {
  constructor(public readonly status: number, public readonly code: string) {
    super(code);
    this.name = 'ApiError';
  }
}

// The CSRF token is not a credential. It lives only in this variable (memory) and is re-fetched on every page load.
let csrfToken: string | null = null;
export const setCsrfToken = (t: string | null) => { csrfToken = t; };

async function request<T>(path: string, init: { method?: string; body?: unknown } = {}): Promise<T> {
  const method = init.method ?? 'GET';
  const headers: Record<string, string> = { Accept: 'application/json' };
  if (method !== 'GET') {
    headers['Content-Type'] = 'application/json';
    if (csrfToken) headers['X-CSRF-Token'] = csrfToken;
  }
  let res: Response;
  try {
    res = await fetch(`${BASE}${path}`, { method, headers, credentials: 'include', body: method === 'GET' ? undefined : JSON.stringify(init.body ?? {}) });
  } catch {
    throw new ApiError(0, 'network');
  }
  const data: unknown = await res.json().catch(() => ({}));
  if (!res.ok) {
    const code = typeof data === 'object' && data && 'error' in data && typeof data.error === 'string' ? data.error : 'error';
    throw new ApiError(res.status, code);
  }
  return data as T;
}

export const loginUrl = `${BASE}/api/auth/instagram/login`;

export interface Limitation { id: string; capability: string; status: 'available' | 'partial' | 'unavailable'; detail: string }
export interface Me {
  user: { username: string; accountType: string | null; role: 'user' | 'admin'; connected: boolean; tokenExpiresAt: string | null };
  session: { expiresAt: string };
  csrfToken: string;
}
export interface SessionRow { id: string; createdAt: string; lastSeenAt: string; expiresAt: string; current: boolean }
export interface Profile { source: string; fetchedAt: string; username: string; accountType: string | null; followersCount: number | null; followsCount: number | null; mediaCount: number | null }

export type CheckStatus = 'pass' | 'fail' | 'needs_review';
export type Severity = 'critical' | 'high' | 'medium' | 'low';
export interface CheckResult {
  id: number; key: string; category: string; title: string; severity: Severity; methods: string[]; verifiedAt: string;
  status: CheckStatus; implementation: string; explanation: string; evidence: string[]; remediation: string[];
}
export interface SecurityReport {
  generatedAt: string; environment: string; scope: string;
  summary: { pass: number; fail: number; needs_review: number; total: number };
  categories: { id: string; index: string; label: string }[];
  checks: CheckResult[]; manualReviewItems: string[];
}
export interface AuditRow { at: string; event: string; outcome: string; userId: string | null }

export const api = {
  limitations: () => request<{ limitations: Limitation[] }>('/api/limitations'),
  me: async () => { const me = await request<Me>('/api/me'); setCsrfToken(me.csrfToken); return me; },
  profile: () => request<Profile>('/api/me/profile'),
  sessions: () => request<{ sessions: SessionRow[] }>('/api/me/sessions'),
  revokeSession: (id: string) => request<{ ok: true }>(`/api/me/sessions/${id}`, { method: 'DELETE' }),
  logout: () => request<{ ok: true }>('/api/auth/logout', { method: 'POST' }),
  logoutAll: () => request<{ ok: true; revoked: number }>('/api/auth/logout-all', { method: 'POST' }),
  disconnect: () => request<{ ok: true }>('/api/me/disconnect', { method: 'POST' }),
  deleteAccount: () => request<{ ok: true }>('/api/me', { method: 'DELETE' }),
  checks: () => request<SecurityReport>('/api/security/checks'),
  runChecks: () => request<SecurityReport>('/api/security/checks/run', { method: 'POST' }),
  audit: () => request<{ events: AuditRow[] }>('/api/security/audit'),
};
