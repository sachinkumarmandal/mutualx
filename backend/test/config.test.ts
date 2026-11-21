import { describe, expect, it } from 'vitest';
import { ConfigError, isWeakSecret, loadConfig } from '../src/config.js';
import { prodEnv, strongEnv } from './helpers.js';

describe('configuration validation', () => {
  it('accepts a strong development config', () => {
    expect(loadConfig(strongEnv()).isProd).toBe(false);
  });

  it('accepts a strong production config', () => {
    const c = loadConfig(prodEnv());
    expect(c.isProd).toBe(true);
    expect(c.meta?.redirectUri).toBe('https://api.example.org/api/auth/instagram/callback');
  });

  it('refuses weak or placeholder secrets in production', () => {
    expect(() => loadConfig(prodEnv({ SESSION_SECRET: 'changeme-changeme-changeme-changeme-1234' }))).toThrow(ConfigError);
    expect(isWeakSecret('a'.repeat(40))).toBe(true);
    expect(isWeakSecret('short')).toBe(true);
  });

  it('requires https, MongoDB and Meta credentials in production', () => {
    expect(() => loadConfig(prodEnv({ FRONTEND_URL: 'http://app.example.org/' }))).toThrow(/https/);
    expect(() => loadConfig(prodEnv({ MONGODB_URI: undefined }))).toThrow(/MONGODB_URI/);
    expect(() => loadConfig(prodEnv({ META_APP_ID: undefined, META_APP_SECRET: undefined, META_REDIRECT_URI: undefined }))).toThrow(/META_/);
  });

  it('rejects a redirect URI that does not match the API origin and callback path', () => {
    expect(() => loadConfig(prodEnv({ META_REDIRECT_URI: 'https://evil.example/api/auth/instagram/callback' }))).toThrow(/META_REDIRECT_URI/);
    expect(() => loadConfig(prodEnv({ META_REDIRECT_URI: 'https://api.example.org/other' }))).toThrow(/META_REDIRECT_URI/);
  });

  it('forbids SameSite=None', () => {
    expect(() => loadConfig(prodEnv({ COOKIE_SAMESITE: 'none' }))).toThrow(ConfigError);
  });

  it('never includes secret values in error messages', () => {
    const secret = 'super-secret-value-that-must-not-leak-1234567890';
    try {
      loadConfig(prodEnv({ SESSION_SECRET: secret, FRONTEND_URL: 'http://insecure.example/' }));
    } catch (e) {
      expect((e as Error).message).not.toContain(secret);
    }
  });

  it('rejects malformed encryption keys', () => {
    expect(() => loadConfig(strongEnv({ ENCRYPTION_KEYS: 'k1:dG9vc2hvcnQ=' }))).toThrow(ConfigError);
    expect(() => loadConfig(strongEnv({ ENCRYPTION_KEYS: 'nokeyid' }))).toThrow(ConfigError);
  });
});
