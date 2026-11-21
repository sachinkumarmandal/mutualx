export type Role = 'user' | 'admin';

/**
 * Data minimisation: this is the complete list of fields MutualX persists per
 * user. No follower/following lists, e-mail, phone or passwords are stored.
 */
export const PERSISTED_USER_FIELDS = [
  'id',
  'igUserId',
  'username',
  'accountType',
  'role',
  'tokenCiphertext',
  'tokenExpiresAt',
  'createdAt',
  'lastLoginAt',
] as const;

export interface UserRecord {
  id: string;
  igUserId: string;
  username: string;
  accountType?: string;
  role: Role;
  /** AES-256-GCM envelope of the long-lived Instagram token; null once disconnected. */
  tokenCiphertext: string | null;
  tokenExpiresAt: Date | null;
  createdAt: Date;
  lastLoginAt: Date;
}

export interface SessionRecord {
  id: string;
  /** SHA-256 of the opaque session token. The token itself is never stored. */
  tokenHash: string;
  prevTokenHash?: string;
  prevValidUntil?: Date;
  userId: string;
  createdAt: Date;
  lastSeenAt: Date;
  rotatedAt: Date;
  expiresAt: Date;
  /** Keyed hashes (HMAC) — raw IP / UA are never stored. */
  ipHash?: string;
  uaHash?: string;
  revokedAt?: Date;
}

export interface OAuthStateRecord {
  stateHash: string;
  bindingHash: string;
  createdAt: Date;
  expiresAt: Date;
}

export type AuditOutcome = 'success' | 'failure' | 'blocked';

export interface AuditRecord {
  id: string;
  at: Date;
  event: string;
  outcome: AuditOutcome;
  userId?: string;
  ipHash?: string;
  meta?: Record<string, string | number | boolean>;
}

export interface Store {
  readonly kind: 'memory' | 'mongo';
  ping(): Promise<boolean>;

  upsertUser(input: Omit<UserRecord, 'id' | 'createdAt'> & { id?: string }): Promise<UserRecord>;
  getUserById(id: string): Promise<UserRecord | null>;
  getUserByIgId(igUserId: string): Promise<UserRecord | null>;
  updateUser(id: string, patch: Partial<Pick<UserRecord, 'tokenCiphertext' | 'tokenExpiresAt' | 'role'>>): Promise<void>;
  /** Deletes the user and every session. Audit entries are retained (they hold no personal data). */
  deleteUser(id: string): Promise<boolean>;

  createSession(record: SessionRecord): Promise<void>;
  findSessionByTokenHash(hash: string, now: Date): Promise<SessionRecord | null>;
  updateSession(id: string, patch: Partial<Omit<SessionRecord, 'id' | 'userId'>>): Promise<void>;
  listSessions(userId: string, now: Date): Promise<SessionRecord[]>;
  revokeSession(id: string, userId: string, now: Date): Promise<boolean>;
  revokeAllSessions(userId: string, now: Date, exceptId?: string): Promise<number>;

  saveOAuthState(record: OAuthStateRecord): Promise<void>;
  /** Atomically fetch-and-delete (single use). */
  consumeOAuthState(stateHash: string, now: Date): Promise<OAuthStateRecord | null>;

  appendAudit(record: AuditRecord): Promise<void>;
  listAudit(limit: number): Promise<AuditRecord[]>;
}
