import type { RequestHandler } from 'express';
import type { AuditLogger } from '../audit/audit.js';
import { AuditEvents } from '../audit/audit.js';

const SCANNER_UA = /(sqlmap|nikto|nmap|masscan|acunetix|nessus|dirbuster|gobuster|wpscan|zgrab|nuclei|havij|openvas)/i;
const PROBE_PATH = /^\/(\.env|\.git|\.aws|\.ssh|wp-admin|wp-login|wp-content|phpmyadmin|xmlrpc\.php|admin\.php|cgi-bin|vendor\/phpunit|actuator|server-status)/i;

const WINDOW_MS = 10 * 60_000;
const STRIKES_TO_BLOCK = 5;
const BLOCK_MS = 15 * 60_000;

interface Entry {
  strikes: number;
  windowStart: number;
  blockedUntil: number;
}

/**
 * Lightweight suspicious-activity detection: known scanner user agents and
 * probes for common vulnerable paths earn "strikes"; repeated strikes from one
 * IP trigger a temporary block. State is per-instance (documented limitation).
 */
export function botGuard(audit: AuditLogger, now: () => number = Date.now): RequestHandler {
  const table = new Map<string, Entry>();

  return (req, res, next) => {
    const ip = req.ip ?? 'unknown';
    const t = now();
    let e = table.get(ip);
    if (e && e.blockedUntil > t) {
      res.status(429).json({ error: 'rate_limited' });
      return;
    }

    const ua = req.get('user-agent') ?? '';
    const suspicious = SCANNER_UA.test(ua) || PROBE_PATH.test(req.path);
    if (!suspicious) return next();

    if (!e || t - e.windowStart > WINDOW_MS) {
      e = { strikes: 0, windowStart: t, blockedUntil: 0 };
      table.set(ip, e);
    }
    e.strikes++;
    if (e.strikes >= STRIKES_TO_BLOCK) e.blockedUntil = t + BLOCK_MS;
    void audit.record(AuditEvents.botSuspected, 'blocked', { ip, meta: { strikes: e.strikes, path: req.path.slice(0, 80) } });

    if (table.size > 10_000) table.clear(); // bound memory
    res.status(404).json({ error: 'not_found' });
  };
}
