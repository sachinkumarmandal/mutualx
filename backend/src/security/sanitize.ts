import type { NextFunction, Request, Response } from 'express';

/**
 * Strict structural input validation applied to every request before it
 * reaches a route handler:
 *  - key allow-list blocks NoSQL operators ($ne, $gt, ...), dotted paths and
 *    prototype pollution vectors;
 *  - credential-looking fields are rejected outright (MutualX is passwordless);
 *  - depth / size / null-byte limits.
 * Route handlers still validate shape and types with strict Zod schemas.
 */
const SAFE_KEY = /^[A-Za-z][A-Za-z0-9_]{0,63}$/;
const FORBIDDEN_KEYS = new Set(['__proto__', 'constructor', 'prototype']);
const CREDENTIAL_KEYS = /^(password|passwd|pwd|pass|passphrase|ig_?password|instagram_?password)$/i;

export type UnsafeReason = 'bad_key' | 'operator_key' | 'credential_field' | 'too_deep' | 'too_large' | 'null_byte' | 'too_long';

export class UnsafeInputError extends Error {
  constructor(public readonly reason: UnsafeReason, public readonly where: string) {
    super(`unsafe input: ${reason}`);
    this.name = 'UnsafeInputError';
  }
}

interface Budget {
  nodes: number;
}

export function inspectValue(value: unknown, where = '$', depth = 0, budget: Budget = { nodes: 0 }): void {
  if (depth > 5) throw new UnsafeInputError('too_deep', where);
  if (++budget.nodes > 400) throw new UnsafeInputError('too_large', where);

  if (typeof value === 'string') {
    if (value.includes('\u0000')) throw new UnsafeInputError('null_byte', where);
    if (value.length > 2048) throw new UnsafeInputError('too_long', where);
    return;
  }
  if (Array.isArray(value)) {
    if (value.length > 50) throw new UnsafeInputError('too_large', where);
    value.forEach((v, i) => inspectValue(v, `${where}[${i}]`, depth + 1, budget));
    return;
  }
  if (value !== null && typeof value === 'object') {
    for (const [key, v] of Object.entries(value)) {
      if (CREDENTIAL_KEYS.test(key)) throw new UnsafeInputError('credential_field', `${where}.${key}`);
      if (key.startsWith('$') || FORBIDDEN_KEYS.has(key)) throw new UnsafeInputError('operator_key', `${where}.${key}`);
      if (!SAFE_KEY.test(key)) throw new UnsafeInputError('bad_key', `${where}.${key.slice(0, 16)}`);
      inspectValue(v, `${where}.${key}`, depth + 1, budget);
    }
  }
}

export function rejectUnsafeInput(onBlocked?: (req: Request, err: UnsafeInputError) => void) {
  return (req: Request, res: Response, next: NextFunction): void => {
    try {
      inspectValue(req.body, 'body');
      inspectValue(req.query, 'query');
      inspectValue(req.params, 'params');
      next();
    } catch (err) {
      if (err instanceof UnsafeInputError) {
        onBlocked?.(req, err);
        res.status(400).json({ error: 'invalid_input' });
        return;
      }
      next(err);
    }
  };
}
