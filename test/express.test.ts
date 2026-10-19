import assert from 'node:assert/strict';
import { request } from 'node:http';
import type { AddressInfo } from 'node:net';
import { after, before, test } from 'node:test';
import express from 'express';
import { authMiddleware } from '../src/express.js';
import { USER_B, USER_A, cookie, mint, newKey, startFakeAuth, type FakeAuth } from './helpers.js';

const key = newKey('k1');
let auth: FakeAuth;
let base: string;
let close: () => Promise<void>;
let userA: string;
let userB: string;

before(async () => {
  auth = await startFakeAuth([key]);
  userA = cookie(await mint(key, auth.url, USER_A));
  userB = cookie(await mint(key, auth.url, USER_B));

  const app = express();
  app.use(
    authMiddleware({
      authUrl: auth.url,
      allow: (u) => u.id === USER_A.id,
      baseUrl: 'https://web.ipcharles.com',
      origins: ['https://web.ipcharles.com'],
      publicPaths: ['/healthz'],
    }),
  );
  app.get('/healthz', (_req, res) => void res.json({ ok: true }));
  app.get('/me', (req, res) => void res.json((req as unknown as { user: unknown }).user));
  app.post('/things', (_req, res) => void res.json({ created: true }));
  const server = app.listen(0, '127.0.0.1');
  await new Promise((r) => server.once('listening', r));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  close = () => new Promise((r) => server.close(() => r()));
});
after(async () => {
  await close();
  await auth.close();
});

/** fetch() forces Sec-Fetch-Mode: cors, so use raw http to behave like a browser navigation. */
const navigate = (path: string, headers: Record<string, string>) =>
  new Promise<{ status: number; location: string | undefined }>((resolve, reject) => {
    request(base + path, { headers }, (res) => {
      res.resume();
      resolve({ status: res.statusCode!, location: res.headers.location });
    })
      .on('error', reject)
      .end();
  });

const get = (path: string, headers: Record<string, string> = {}) => fetch(base + path, { redirect: 'manual', headers });

test('express: allowed user passes and req.user is set', async () => {
  const res = await get('/me', { cookie: userA, accept: 'application/json' });
  assert.equal(res.status, 200);
  assert.deepEqual(await res.json(), USER_A);
});

test('express: navigations redirect, API calls get 401, outsiders get 403', async () => {
  const nav = await navigate('/me?x=1', { accept: 'text/html', 'sec-fetch-mode': 'navigate' });
  assert.equal(nav.status, 302);
  const loc = new URL(nav.location!);
  assert.equal(loc.searchParams.get('return'), 'https://web.ipcharles.com/me?x=1');

  assert.equal((await get('/me', { accept: 'application/json' })).status, 401);
  assert.equal((await get('/me', { cookie: userB, accept: 'application/json' })).status, 403);
  assert.equal((await get('/healthz')).status, 200);
});

test('express: Origin is enforced on POST', async () => {
  const post = (origin?: string) =>
    fetch(base + '/things', { method: 'POST', headers: { cookie: userA, accept: 'application/json', ...(origin ? { origin } : {}) } });
  assert.equal((await post('https://web.ipcharles.com')).status, 200);
  assert.equal((await post('https://app.ipcharles.com')).status, 403);
  assert.equal((await post()).status, 403);
});
