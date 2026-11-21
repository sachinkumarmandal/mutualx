import { expect, test, type Page, type Route } from '@playwright/test';
import path from 'node:path';

const fx = (n: string) => path.join(import.meta.dirname, 'fixtures', n);
const API = 'http://localhost:8080';
const cors = { 'access-control-allow-origin': 'http://localhost:4173', 'access-control-allow-credentials': 'true', 'content-type': 'application/json' };
const json = (route: Route, status: number, body: unknown) => route.fulfill({ status, headers: cors, body: JSON.stringify(body) });

/** UI tests: API responses are stubbed here to exercise rendering. They are test fixtures, not product data. */
async function stubApi(page: Page, opts: { role?: 'admin' | 'user' | null } = {}) {
  await page.route(`${API}/api/limitations`, (r) => json(r, 200, { limitations: [{ id: 'follower_lists', capability: 'List of your followers', status: 'unavailable', detail: 'Not exposed by official APIs.' }] }));
  await page.route(`${API}/api/me`, (r) => (opts.role ? json(r, 200, { user: { username: 'tester', accountType: 'BUSINESS', role: opts.role, connected: true, tokenExpiresAt: null }, session: { expiresAt: new Date(Date.now() + 36e5).toISOString() }, csrfToken: 'tok' }) : json(r, 401, { error: 'unauthorized' })));
  await page.route(`${API}/api/security/audit`, (r) => json(r, 200, { events: [] }));
  await page.route(`${API}/api/security/checks`, (r) =>
    json(r, 200, {
      generatedAt: new Date().toISOString(), environment: 'test', scope: 'test',
      summary: { pass: 1, fail: 1, needs_review: 1, total: 3 },
      categories: [{ id: 'injection', index: '01', label: 'Injection & Input' }],
      checks: [
        { id: 1, key: 'a', category: 'injection', title: 'SQL Injection Protection', severity: 'critical', methods: ['runtime-probe'], verifiedAt: new Date().toISOString(), status: 'pass', implementation: 'impl A', explanation: 'expl A', evidence: ['ev A'], remediation: ['rem A'] },
        { id: 2, key: 'b', category: 'injection', title: 'XSS Protection', severity: 'high', methods: ['static-scan'], verifiedAt: new Date().toISOString(), status: 'fail', implementation: 'impl B', explanation: 'expl B', evidence: ['ev B'], remediation: ['rem B'] },
        { id: 3, key: 'c', category: 'injection', title: 'CSRF Protection', severity: 'high', methods: ['runtime-probe'], verifiedAt: new Date().toISOString(), status: 'needs_review', implementation: 'impl C', explanation: 'expl C', evidence: ['ev C'], remediation: ['rem C'] },
      ],
      manualReviewItems: ['Branch protection enabled'],
    }),
  );
}

test('computes mutuals from export files without sending them anywhere', async ({ page }) => {
  await stubApi(page);
  const writes: string[] = [];
  page.on('request', (r) => { if (r.method() !== 'GET') writes.push(`${r.method()} ${r.url()}`); });

  await page.goto('/');
  await page.locator('input[type=file]').nth(0).setInputFiles(fx('followers_1.json'));
  await page.locator('input[type=file]').nth(1).setInputFiles(fx('following.json'));

  await expect(page.getByTestId('count-mutuals')).toHaveText('2');
  await expect(page.getByTestId('count-notFollowingBack')).toHaveText('2');
  await expect(page.getByTestId('count-fans')).toHaveText('2');
  await expect(page.getByTestId('result-list').getByText('@ben')).toBeVisible();

  await page.getByRole('tab', { name: /Not following back/ }).click();
  await expect(page.getByTestId('result-list').getByText('@eli')).toBeVisible();
  await page.getByLabel('Search usernames').fill('fa');
  await expect(page.getByTestId('result-list').locator('li')).toHaveCount(1);

  expect(writes, 'no non-GET request may be made while analysing').toEqual([]);
});

test('rejects non-JSON files with a clear message', async ({ page }) => {
  await stubApi(page);
  await page.goto('/');
  await page.locator('input[type=file]').nth(0).setInputFiles(fx('not-json.html'));
  await expect(page.getByRole('alert')).toContainText('not a .json file');
});

test('shows the honest API limitations', async ({ page }) => {
  await stubApi(page);
  await page.goto('/');
  await expect(page.getByText('List of your followers')).toBeVisible();
  await expect(page.getByText('unavailable').first()).toBeVisible();
});

test('says so plainly when the API is unreachable instead of faking data', async ({ page }) => {
  await page.route(`${API}/**`, (r) => r.abort());
  await page.goto('/');
  await expect(page.getByText(/API is not reachable/)).toBeVisible();
});

test('security dashboard is hidden from visitors and shows real statuses to admins', async ({ page }) => {
  await stubApi(page);
  await page.goto('/#/security');
  await expect(page.getByRole('heading', { name: 'Admin sign-in required' })).toBeVisible();

  await page.unroute(`${API}/api/me`);
  await stubApi(page, { role: 'admin' });
  await page.goto('/#/security');
  await page.reload();
  await expect(page.getByRole('heading', { name: '20-point security dashboard' })).toBeVisible();
  await expect(page.getByText('Fail', { exact: true }).first()).toBeVisible();
  await page.getByRole('button', { name: /XSS Protection/ }).click();
  await expect(page.getByText('expl B')).toBeVisible();
  await page.getByRole('button', { name: 'Fail', exact: false }).filter({ hasText: /^Fail/ }).click();
  await expect(page.getByRole('button', { name: /SQL Injection/ })).toHaveCount(0);
});

test('non-admins are told the dashboard is admin-only', async ({ page }) => {
  await stubApi(page, { role: 'user' });
  await page.goto('/#/security');
  await expect(page.getByRole('heading', { name: 'Administrators only' })).toBeVisible();
});

test('compares with an older export and shows new and lost followers', async ({ page }) => {
  await stubApi(page);
  await page.goto('/');
  await page.locator('input[type=file]').nth(0).setInputFiles(fx('followers_1.json')); // ana ben cy dee
  await page.locator('input[type=file]').nth(1).setInputFiles(fx('following.json'));
  await page.locator('summary', { hasText: 'compare with an older export' }).click();
  await page.locator('input[type=file]').nth(2).setInputFiles(fx('followers_old.json')); // ben cy dee zed
  await expect(page.getByTestId('count-newFollowers')).toHaveText('1'); // ana
  await expect(page.getByTestId('count-lostFollowers')).toHaveText('1'); // zed
  await page.getByRole('tab', { name: /Lost followers/ }).click();
  await expect(page.getByTestId('result-list').getByText('@zed')).toBeVisible();
});

test('shows stats and can reverse the sort order', async ({ page }) => {
  await stubApi(page);
  await page.goto('/');
  await page.getByRole('button', { name: 'Try with example data' }).click();
  await expect(page.getByText(/example data, not a real account/)).toBeVisible();
  await expect(page.getByTestId('stats')).toContainText('They follow you back');
  const first = page.getByTestId('result-list').locator('li').first();
  const before = await first.innerText();
  await page.getByRole('button', { name: 'Toggle sort order' }).click();
  expect(await first.innerText()).not.toBe(before);
});
