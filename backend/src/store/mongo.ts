import mongoose, { Schema, type Model } from 'mongoose';
import { randomUUID } from 'node:crypto';
import type { AuditRecord, OAuthStateRecord, SessionRecord, Store, UserRecord } from './types.js';

/**
 * MongoDB store. Hardening applied here:
 *  - `sanitizeFilter` + `strictQuery`: query operators in user-controlled values are neutralised;
 *  - every filter value is cast with String()/Date before use (no raw objects reach the driver);
 *  - schemas are `strict: 'throw'` with required fields, enums and regex validators;
 *  - TTL indexes enforce retention (sessions, OAuth state, audit);
 *  - tokens are stored only as ciphertext / hashes.
 */
mongoose.set('sanitizeFilter', true);
mongoose.set('strictQuery', true);

const opts = { strict: 'throw', versionKey: false } as const;

const userSchema = new Schema<UserRecord & { _id: string }>(
  {
    _id: { type: String, required: true },
    igUserId: { type: String, required: true, unique: true, match: /^\d{1,32}$/ },
    username: { type: String, required: true, maxlength: 64, match: /^[A-Za-z0-9._]{1,64}$/ },
    accountType: { type: String, enum: ['BUSINESS', 'MEDIA_CREATOR', 'PERSONAL'] },
    role: { type: String, required: true, enum: ['user', 'admin'] },
    tokenCiphertext: { type: String, default: null, maxlength: 2048 },
    tokenExpiresAt: { type: Date, default: null },
    createdAt: { type: Date, required: true },
    lastLoginAt: { type: Date, required: true },
  },
  opts,
);

const sessionSchema = new Schema<SessionRecord & { _id: string }>(
  {
    _id: { type: String, required: true },
    tokenHash: { type: String, required: true, unique: true, match: /^[a-f0-9]{64}$/ },
    prevTokenHash: { type: String, match: /^[a-f0-9]{64}$/, index: true, sparse: true },
    prevValidUntil: { type: Date },
    userId: { type: String, required: true, index: true },
    createdAt: { type: Date, required: true },
    lastSeenAt: { type: Date, required: true },
    rotatedAt: { type: Date, required: true },
    expiresAt: { type: Date, required: true, index: { expireAfterSeconds: 0 } },
    ipHash: { type: String, maxlength: 64 },
    uaHash: { type: String, maxlength: 64 },
    revokedAt: { type: Date },
  },
  opts,
);

const stateSchema = new Schema<OAuthStateRecord>(
  {
    stateHash: { type: String, required: true, unique: true, match: /^[a-f0-9]{64}$/ },
    bindingHash: { type: String, required: true, match: /^[a-f0-9]{64}$/ },
    createdAt: { type: Date, required: true },
    expiresAt: { type: Date, required: true, index: { expireAfterSeconds: 0 } },
  },
  opts,
);

export function buildAuditSchema(retentionDays: number) {
  return new Schema<AuditRecord & { _id: string }>(
    {
      _id: { type: String, required: true },
      at: { type: Date, required: true, index: { expireAfterSeconds: retentionDays * 86_400 } },
      event: { type: String, required: true, maxlength: 64, match: /^[a-z0-9_.:-]+$/ },
      outcome: { type: String, required: true, enum: ['success', 'failure', 'blocked'] },
      userId: { type: String },
      ipHash: { type: String, maxlength: 64 },
      meta: { type: Schema.Types.Mixed },
    },
    opts,
  );
}

type Lean<T> = T & { _id: string };

function toUser(d: Lean<UserRecord>): UserRecord {
  const { _id, ...rest } = d;
  return { ...rest, id: _id };
}
function toSession(d: Lean<SessionRecord>): SessionRecord {
  const { _id, ...rest } = d;
  return { ...rest, id: _id };
}

export class MongoStore implements Store {
  readonly kind = 'mongo' as const;
  // Models are intentionally loosely typed: schemas (above) are the source of truth for validation.
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  private users: Model<any>;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  private sessions: Model<any>;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  private states: Model<any>;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  private auditM: Model<any>;

  private constructor(private conn: mongoose.Connection, retentionDays: number) {
    this.users = conn.model('User', userSchema) as unknown as Model<any>; // eslint-disable-line @typescript-eslint/no-explicit-any
    this.sessions = conn.model('Session', sessionSchema) as unknown as Model<any>; // eslint-disable-line @typescript-eslint/no-explicit-any
    this.states = conn.model('OAuthState', stateSchema) as unknown as Model<any>; // eslint-disable-line @typescript-eslint/no-explicit-any
    this.auditM = conn.model('Audit', buildAuditSchema(retentionDays)) as unknown as Model<any>; // eslint-disable-line @typescript-eslint/no-explicit-any
  }

  static async connect(uri: string, retentionDays: number): Promise<MongoStore> {
    const conn = await mongoose.createConnection(uri, {
      serverSelectionTimeoutMS: 8000,
      maxPoolSize: 10,
      autoIndex: true,
      retryWrites: true,
    }).asPromise();
    const store = new MongoStore(conn, retentionDays);
    await Promise.all([store.users.init(), store.sessions.init(), store.states.init(), store.auditM.init()]);
    return store;
  }

  async close(): Promise<void> {
    await this.conn.close();
  }

  async ping(): Promise<boolean> {
    try {
      await this.conn.db?.admin().ping();
      return true;
    } catch {
      return false;
    }
  }

  async upsertUser(input: Omit<UserRecord, 'id' | 'createdAt'> & { id?: string }): Promise<UserRecord> {
    const now = new Date();
    const doc = await this.users
      .findOneAndUpdate(
        { igUserId: String(input.igUserId) },
        {
          $set: {
            username: String(input.username),
            accountType: input.accountType,
            role: input.role,
            tokenCiphertext: input.tokenCiphertext,
            tokenExpiresAt: input.tokenExpiresAt,
            lastLoginAt: input.lastLoginAt,
          },
          $setOnInsert: { _id: input.id ?? randomUUID(), createdAt: now },
        },
        { upsert: true, new: true, runValidators: true },
      )
      .lean<Lean<UserRecord>>();
    return toUser(doc!);
  }

  async getUserById(id: string): Promise<UserRecord | null> {
    const d = await this.users.findOne({ _id: String(id) }).lean<Lean<UserRecord>>();
    return d ? toUser(d) : null;
  }

  async getUserByIgId(igUserId: string): Promise<UserRecord | null> {
    const d = await this.users.findOne({ igUserId: String(igUserId) }).lean<Lean<UserRecord>>();
    return d ? toUser(d) : null;
  }

  async updateUser(id: string, patch: Partial<Pick<UserRecord, 'tokenCiphertext' | 'tokenExpiresAt' | 'role'>>): Promise<void> {
    await this.users.updateOne({ _id: String(id) }, { $set: patch }, { runValidators: true });
  }

  async deleteUser(id: string): Promise<boolean> {
    const res = await this.users.deleteOne({ _id: String(id) });
    await this.sessions.deleteMany({ userId: String(id) });
    return res.deletedCount > 0;
  }

  async createSession(record: SessionRecord): Promise<void> {
    const { id, ...rest } = record;
    await this.sessions.create({ ...rest, _id: id });
  }

  async findSessionByTokenHash(hash: string, now: Date): Promise<SessionRecord | null> {
    const h = String(hash);
    const d = await this.sessions
      .findOne({ $or: [{ tokenHash: h }, { prevTokenHash: h, prevValidUntil: { $gt: now } }] })
      .lean<Lean<SessionRecord>>();
    return d ? toSession(d) : null;
  }

  async updateSession(id: string, patch: Partial<Omit<SessionRecord, 'id' | 'userId'>>): Promise<void> {
    await this.sessions.updateOne({ _id: String(id) }, { $set: patch }, { runValidators: true });
  }

  async listSessions(userId: string, now: Date): Promise<SessionRecord[]> {
    const ds = await this.sessions
      .find({ userId: String(userId), revokedAt: { $exists: false }, expiresAt: { $gt: now } })
      .sort({ lastSeenAt: -1 })
      .limit(50)
      .lean<Lean<SessionRecord>[]>();
    return ds.map(toSession);
  }

  async revokeSession(id: string, userId: string, now: Date): Promise<boolean> {
    const r = await this.sessions.updateOne({ _id: String(id), userId: String(userId), revokedAt: { $exists: false } }, { $set: { revokedAt: now } });
    return r.modifiedCount > 0;
  }

  async revokeAllSessions(userId: string, now: Date, exceptId?: string): Promise<number> {
    const filter: Record<string, unknown> = { userId: String(userId), revokedAt: { $exists: false } };
    if (exceptId) filter._id = { $ne: String(exceptId) };
    const r = await this.sessions.updateMany(filter, { $set: { revokedAt: now } });
    return r.modifiedCount;
  }

  async saveOAuthState(record: OAuthStateRecord): Promise<void> {
    await this.states.create(record);
  }

  async consumeOAuthState(stateHash: string, now: Date): Promise<OAuthStateRecord | null> {
    const d = await this.states.findOneAndDelete({ stateHash: String(stateHash) }).lean<OAuthStateRecord>();
    return d && d.expiresAt > now ? d : null;
  }

  async appendAudit(record: AuditRecord): Promise<void> {
    const { id, ...rest } = record;
    await this.auditM.create({ ...rest, _id: id });
  }

  async listAudit(limit: number): Promise<AuditRecord[]> {
    const ds = await this.auditM.find({}).sort({ at: -1 }).limit(Math.min(Math.max(1, Math.floor(limit)), 500)).lean<Lean<AuditRecord>[]>();
    return ds.map(({ _id, ...rest }) => ({ ...rest, id: _id }));
  }
}
