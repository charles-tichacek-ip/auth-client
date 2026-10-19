import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';
import Fastify, { type FastifyInstance } from 'fastify';
import { authPlugin } from '../src/fastify.js';
import { USER_B, USER_A, cookie, mint, newKey, startFakeAuth, type FakeAuth } from './helpers.js';

const key = newKey('k1');
let auth: FakeAuth;
let userA: string;
let userB: string;

before(async () => {
  auth = await startFakeAuth([key]);
  userA = cookie(await mint(key, auth.url, USER_A));
  userB = cookie(await mint(key, auth.url, USER_B));
});
after(() => auth.close());

const ALLOWED = new Set([USER_A.id]);

async function makeApp(extra: Record<string, unknown> = {}): Promise<FastifyInstance> {
  const app = Fastify();
  await app.register(authPlugin, {
    authUrl: auth.url,
    allow: (u) => ALLOWED.has(u.id),
    baseUrl: 'https://app.ipcharles.com',
    origins: ['https://app.ipcharles.com'],
    publicPaths: ['/healthz'],
    ...extra,
  });
  app.get('/healthz', async (request) => ({ ok: true, user: request.user?.name ?? null }));
  app.get('/page', async (request) => ({ hello: request.user!.name, id: request.user!.id }));
  app.get('/open', { config: { public: true } }, async (request) => ({ user: request.user?.name ?? null }));
  app.post('/things', async (request) => ({ created: true, by: request.user!.id }));
  app.delete('/things/1', async () => ({ deleted: true }));
  return app;
}

const html = { accept: 'text/html,application/xhtml+xml', 'sec-fetch-mode': 'navigate' };
const json = { accept: 'application/json' };

test('signed-in, allowed user reaches the route with request.user set', async () => {
  const app = await makeApp();
  const res = await app.inject({ url: '/page', headers: { ...json, cookie: userA } });
  assert.equal(res.statusCode, 200);
  assert.deepEqual(res.json(), { hello: 'User A', id: USER_A.id });
});

test('browser navigation without a session redirects to the auth login and back to the same URL', async () => {
  const app = await makeApp();
  const res = await app.inject({ url: '/page?tab=2', headers: html });
  assert.equal(res.statusCode, 302);
  const loc = new URL(res.headers.location as string);
  assert.equal(loc.origin, auth.url);
  assert.equal(loc.pathname, '/login');
  assert.equal(loc.searchParams.get('return'), 'https://app.ipcharles.com/page?tab=2');
});

test('fetch/XHR callers get 401 JSON instead of a redirect', async () => {
  const app = await makeApp();
  for (const headers of [json, { accept: '*/*' }, { accept: 'text/html', 'sec-fetch-mode': 'cors' }, {}]) {
    const res = await app.inject({ url: '/page', headers });
    assert.equal(res.statusCode, 401, JSON.stringify(headers));
    assert.deepEqual(res.json(), { error: 'unauthenticated' });
  }
});

test('invalid, forged and expired cookies are treated as signed out', async () => {
  const app = await makeApp();
  const forged = cookie(await mint(newKey('k1'), auth.url));
  const expired = cookie(await mint(key, auth.url, USER_A, { exp: Math.floor(Date.now() / 1000) - 5 }));
  for (const c of ['ipc_session=junk', forged, expired]) {
    assert.equal((await app.inject({ url: '/page', headers: { ...json, cookie: c } })).statusCode, 401);
    assert.equal((await app.inject({ url: '/page', headers: { ...html, cookie: c } })).statusCode, 302);
  }
});

test('a signed-in user who is not on the allowlist gets 403', async () => {
  const app = await makeApp();
  for (const headers of [json, html]) {
    const res = await app.inject({ url: '/page', headers: { ...headers, cookie: userB } });
    assert.equal(res.statusCode, 403);
    assert.deepEqual(res.json(), { error: 'forbidden' });
  }
});

test('async allow functions are awaited', async () => {
  const app = await makeApp({ allow: async (u: { id: string }) => u.id === USER_B.id });
  assert.equal((await app.inject({ url: '/page', headers: { ...json, cookie: userB } })).statusCode, 200);
  assert.equal((await app.inject({ url: '/page', headers: { ...json, cookie: userA } })).statusCode, 403);
});

test('state-changing requests must come from an allowed Origin', async () => {
  const app = await makeApp();
  const post = (origin?: string) =>
    app.inject({ method: 'POST', url: '/things', headers: { ...json, cookie: userA, ...(origin ? { origin } : {}) } });

  assert.equal((await post('https://app.ipcharles.com')).statusCode, 200);
  assert.equal((await post('https://evil.ipcharles.com')).statusCode, 403, 'another subdomain');
  assert.equal((await post('https://app.ipcharles.com.evil.com')).statusCode, 403);
  assert.equal((await post('http://app.ipcharles.com')).statusCode, 403, 'wrong scheme');
  assert.equal((await post('null')).statusCode, 403);
  const missing = await post();
  assert.equal(missing.statusCode, 403);
  assert.deepEqual(missing.json(), { error: 'bad_origin' });
  const del = await app.inject({ method: 'DELETE', url: '/things/1', headers: { ...json, cookie: userA, origin: 'https://evil.ipcharles.com' } });
  assert.equal(del.statusCode, 403);

  // GET is never origin-checked.
  assert.equal((await app.inject({ url: '/page', headers: { ...json, cookie: userA, origin: 'https://evil.ipcharles.com' } })).statusCode, 200);
});

test('Origin defaults to the app itself, and can allow missing Origin for non-browser callers', async () => {
  const own = await makeApp({ origins: undefined });
  const ok = await own.inject({ method: 'POST', url: '/things', headers: { ...json, cookie: userA, origin: 'https://app.ipcharles.com' } });
  assert.equal(ok.statusCode, 200);
  const bad = await own.inject({ method: 'POST', url: '/things', headers: { ...json, cookie: userA, origin: 'https://api.ipcharles.com' } });
  assert.equal(bad.statusCode, 403);

  const lenient = await makeApp({ allowMissingOrigin: true });
  assert.equal((await lenient.inject({ method: 'POST', url: '/things', headers: { ...json, cookie: userA } })).statusCode, 200);
  assert.equal((await lenient.inject({ method: 'POST', url: '/things', headers: { ...json, cookie: userA, origin: 'https://evil.com' } })).statusCode, 403, 'a present but wrong Origin still fails');
});

test('the Origin check runs before authentication', async () => {
  const app = await makeApp();
  const res = await app.inject({ method: 'POST', url: '/things', headers: { ...json, origin: 'https://evil.ipcharles.com' } });
  assert.equal(res.statusCode, 403);
});

test('publicPaths and config.public routes skip enforcement but still attach a valid user', async () => {
  const app = await makeApp();
  assert.deepEqual((await app.inject({ url: '/healthz' })).json(), { ok: true, user: null });
  assert.deepEqual((await app.inject({ url: '/healthz', headers: { cookie: userA } })).json(), { ok: true, user: 'User A' });
  assert.deepEqual((await app.inject({ url: '/open' })).json(), { user: null });
  assert.deepEqual((await app.inject({ url: '/open', headers: { cookie: userA } })).json(), { user: 'User A' });
  // public does not mean the allowlist is skipped for identification only: no user is invented
  assert.deepEqual((await app.inject({ url: '/open', headers: { cookie: 'ipc_session=junk' } })).json(), { user: null });
});

test('CORS preflights pass through untouched', async () => {
  const app = await makeApp();
  app.options('/things', async (_req, reply) => reply.code(204).send());
  const res = await app.inject({ method: 'OPTIONS', url: '/things', headers: { origin: 'https://app.ipcharles.com', 'access-control-request-method': 'POST' } });
  assert.equal(res.statusCode, 204);
});

test('registering without `allow` fails loudly', async () => {
  const app = Fastify();
  await assert.rejects(async () => {
    await app.register(authPlugin, { authUrl: auth.url } as never);
    await app.ready();
  }, /allow/);
});

test('hooks apply to the registering scope, so an encapsulated scope protects only some routes', async () => {
  const app = Fastify();
  app.get('/public', async () => ({ ok: true }));
  await app.register(async (scope) => {
    await scope.register(authPlugin, { authUrl: auth.url, allow: () => true, baseUrl: 'https://app.ipcharles.com' });
    scope.get('/private', async (request) => ({ user: request.user!.name }));
  });
  assert.equal((await app.inject({ url: '/public' })).statusCode, 200);
  assert.equal((await app.inject({ url: '/private', headers: json })).statusCode, 401);
  assert.equal((await app.inject({ url: '/private', headers: { ...json, cookie: userA } })).statusCode, 200);
});

test('without baseUrl the return address comes from the request host', async () => {
  const app = await makeApp({ baseUrl: undefined, origins: undefined });
  const res = await app.inject({ url: '/page', headers: { ...html, host: 'app.ipcharles.com' } });
  const loc = new URL(res.headers.location as string);
  assert.match(loc.searchParams.get('return')!, /^http:\/\/app\.ipcharles\.com\/page$/);
});
