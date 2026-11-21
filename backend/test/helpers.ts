import { randomBytes } from 'node:crypto';
import { loadConfig, type AppConfig } from '../src/config.js';

export function strongEnv(overrides: Record<string, string | undefined> = {}): NodeJS.ProcessEnv {
  return {
    NODE_ENV: 'test',
    FRONTEND_URL: 'http://localhost:5173/',
    API_PUBLIC_URL: 'http://localhost:8080',
    SESSION_SECRET: randomBytes(48).toString('base64url'),
    ENCRYPTION_KEYS: `k1:${randomBytes(32).toString('base64')}`,
    LOG_LEVEL: 'silent',
    ...overrides,
  } as NodeJS.ProcessEnv;
}

export function testConfig(overrides: Record<string, string | undefined> = {}): AppConfig {
  return loadConfig(strongEnv(overrides));
}

export const prodEnv = (overrides: Record<string, string | undefined> = {}) =>
  strongEnv({
    NODE_ENV: 'production',
    FRONTEND_URL: 'https://app.example.org/',
    API_PUBLIC_URL: 'https://api.example.org',
    MONGODB_URI: 'mongodb+srv://svc_mutualx:Zk3pQ9vT7mXw2LrN8sBd@cluster0.example.mongodb.net/mutualx',
    META_APP_ID: '1234567890123',
    META_APP_SECRET: randomBytes(16).toString('hex'),
    META_REDIRECT_URI: 'https://api.example.org/api/auth/instagram/callback',
    ...overrides,
  });
