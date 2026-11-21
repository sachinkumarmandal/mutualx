import { Router } from 'express';
import type { Deps } from '../deps.js';

/**
 * Honest capability statement shown in the UI. MutualX does not scrape
 * Instagram and cannot compute mutual followers with official APIs alone.
 * Verify against Meta's current documentation before relying on this list.
 */
export const LIMITATIONS = [
  { id: 'oauth', capability: 'Sign in with Instagram (official OAuth)', status: 'available', detail: 'Uses Meta’s official authorization flow. MutualX never sees or stores your Instagram password.' },
  { id: 'professional_only', capability: 'Account types', status: 'partial', detail: 'The Instagram API with Instagram Login serves Business and Creator (professional) accounts. Personal accounts may not be able to connect.' },
  { id: 'own_profile', capability: 'Your own profile and aggregate counts', status: 'available', detail: 'Username, account type, follower count, following count and media count can be read live for the connected account.' },
  { id: 'follower_lists', capability: 'List of your followers / accounts you follow', status: 'unavailable', detail: 'Meta’s official APIs do not expose follower or following lists, so MutualX cannot read them.' },
  { id: 'export_mutuals', capability: 'Mutuals from your own Instagram data export', status: 'available', detail: 'You download your followers and following JSON from Instagram’s “Export your information” tool and drop it into MutualX. The comparison runs in your browser; the files are never uploaded or stored.' },
  { id: 'mutuals', capability: 'Mutual followers fetched automatically from Instagram', status: 'unavailable', detail: 'Computing mutuals requires follower lists of both accounts, which no official API provides. MutualX will not scrape or bypass Meta restrictions to obtain them.' },
  { id: 'other_accounts', capability: 'Data about other people’s accounts', status: 'unavailable', detail: 'Only the account that authorised MutualX is accessible, and only within the granted permissions.' },
  { id: 'unfollowers', capability: 'Who unfollowed you / profile visitors', status: 'unavailable', detail: 'Not exposed by official APIs.' },
] as const;

export function publicRouter(deps: Deps): Router {
  const r = Router();

  r.get('/health', async (_req, res) => {
    const ok = await deps.store.ping();
    res.status(ok ? 200 : 503).json({ status: ok ? 'ok' : 'degraded' });
  });

  r.get('/limitations', (_req, res) => {
    res.json({ limitations: LIMITATIONS });
  });

  return r;
}
