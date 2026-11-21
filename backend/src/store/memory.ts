import { randomUUID } from 'node:crypto';
import type { AuditRecord, OAuthStateRecord, SessionRecord, Store, UserRecord } from './types.js';

/** In-memory store used for tests, local development and security probes. */
export class MemoryStore implements Store {
  readonly kind = 'memory' as const;
  users = new Map<string, UserRecord>();
  sessions = new Map<string, SessionRecord>();
  states = new Map<string, OAuthStateRecord>();
  audit: AuditRecord[] = [];

  async ping(): Promise<boolean> {
    return true;
  }

  async upsertUser(input: Omit<UserRecord, 'id' | 'createdAt'> & { id?: string }): Promise<UserRecord> {
    const existing = await this.getUserByIgId(input.igUserId);
    const record: UserRecord = existing
      ? { ...existing, ...input, id: existing.id, createdAt: existing.createdAt }
      : { ...input, id: input.id ?? randomUUID(), createdAt: new Date() };
    this.users.set(record.id, record);
    return { ...record };
  }

  async getUserById(id: string): Promise<UserRecord | null> {
    const u = this.users.get(id);
    return u ? { ...u } : null;
  }

  async getUserByIgId(igUserId: string): Promise<UserRecord | null> {
    for (const u of this.users.values()) if (u.igUserId === igUserId) return { ...u };
    return null;
  }

  async updateUser(id: string, patch: Partial<Pick<UserRecord, 'tokenCiphertext' | 'tokenExpiresAt' | 'role'>>): Promise<void> {
    const u = this.users.get(id);
    if (u) this.users.set(id, { ...u, ...patch });
  }

  async deleteUser(id: string): Promise<boolean> {
    const had = this.users.delete(id);
    for (const [sid, s] of this.sessions) if (s.userId === id) this.sessions.delete(sid);
    return had;
  }

  async createSession(record: SessionRecord): Promise<void> {
    this.sessions.set(record.id, { ...record });
  }

  async findSessionByTokenHash(hash: string, now: Date): Promise<SessionRecord | null> {
    for (const s of this.sessions.values()) {
      if (s.tokenHash === hash) return { ...s };
      if (s.prevTokenHash === hash && s.prevValidUntil && s.prevValidUntil > now) return { ...s };
    }
    return null;
  }

  async updateSession(id: string, patch: Partial<Omit<SessionRecord, 'id' | 'userId'>>): Promise<void> {
    const s = this.sessions.get(id);
    if (s) this.sessions.set(id, { ...s, ...patch });
  }

  async listSessions(userId: string, now: Date): Promise<SessionRecord[]> {
    return [...this.sessions.values()].filter((s) => s.userId === userId && !s.revokedAt && s.expiresAt > now).map((s) => ({ ...s }));
  }

  async revokeSession(id: string, userId: string, now: Date): Promise<boolean> {
    const s = this.sessions.get(id);
    if (!s || s.userId !== userId || s.revokedAt) return false;
    this.sessions.set(id, { ...s, revokedAt: now });
    return true;
  }

  async revokeAllSessions(userId: string, now: Date, exceptId?: string): Promise<number> {
    let n = 0;
    for (const [id, s] of this.sessions) {
      if (s.userId === userId && id !== exceptId && !s.revokedAt) {
        this.sessions.set(id, { ...s, revokedAt: now });
        n++;
      }
    }
    return n;
  }

  async saveOAuthState(record: OAuthStateRecord): Promise<void> {
    this.states.set(record.stateHash, { ...record });
  }

  async consumeOAuthState(stateHash: string, now: Date): Promise<OAuthStateRecord | null> {
    const s = this.states.get(stateHash);
    if (!s) return null;
    this.states.delete(stateHash);
    return s.expiresAt > now ? s : null;
  }

  async appendAudit(record: AuditRecord): Promise<void> {
    this.audit.push({ ...record });
    if (this.audit.length > 5000) this.audit.shift();
  }

  async listAudit(limit: number): Promise<AuditRecord[]> {
    return this.audit.slice(-limit).reverse();
  }
}
