import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';
import { SignJWT } from 'jose';
import { createAuthClient, cookieValues, verifySession, wantsRedirect } from '../src/index.js';
import { USER_A, cookie, mint, newKey, startFakeAuth, type FakeAuth } from './helpers.js';

const key = newKey('k1');
let auth: FakeAuth;

before(async () => {
  auth = await startFakeAuth([key]);
});
after(() => auth.close());

const allowAll = () => true;
const BASE = 'https://app.ipcharles.com';
const client = () => createAuthClient({ authUrl: auth.url, allow: allowAll });

test('a valid session cookie verifies to {id, name}', async () => {
  const token = await mint(key, auth.url);
  assert.deepEqual(await client().verifySession(cookie(token)), USER_A);
});

test('missing, malformed, forged, expired, wrong-issuer and unknown-kid tokens are rejected', async () => {
  const c = client();
  const other = newKey('k1'); // same kid, different key
  assert.equal(await c.verifySession(undefined), null);
  assert.equal(await c.verifySession(''), null);
  assert.equal(await c.verifySession('ipc_session=garbage'), null);
  assert.equal(await c.verifySession(cookie(await mint(other, auth.url))), null, 'forged');
  assert.equal(await c.verifySession(cookie(await mint(key, auth.url, USER_A, { exp: Math.floor(Date.now() / 1000) - 5 }))), null, 'expired');
  assert.equal(await c.verifySession(cookie(await mint(key, auth.url, USER_A, { iss: 'https://evil.example' }))), null, 'issuer');
  assert.equal(await c.verifySession(cookie(await mint(key, auth.url, USER_A, { kid: 'nope' }))), null, 'unknown kid');

  const good = await mint(key, auth.url);
  const [h, p] = good.split('.');
  const none = Buffer.from(JSON.stringify({ alg: 'none', kid: 'k1' })).toString('base64url');
  assert.equal(await c.verifySession(cookie(`${none}.${p}.`)), null, 'alg none');
  assert.equal(await c.verifySession(cookie(`${h}.${p}.`)), null, 'stripped signature');
  const hs = await new SignJWT({ name: 'X' }).setProtectedHeader({ alg: 'HS256', kid: 'k1' }).setIssuer(auth.url).setSubject('u').setExpirationTime('1h').sign(new TextEncoder().encode('secret-secret-secret-secret-secret!'));
  assert.equal(await c.verifySession(cookie(hs)), null, 'HS256 downgrade');
});

test('cookie name follows the auth URL scheme and can be overridden', async () => {
  assert.equal(createAuthClient({ authUrl: 'https://auth.ipcharles.com', allow: allowAll, baseUrl: BASE }).cookieName, '__Secure-ipc_session');
  assert.equal(createAuthClient({ authUrl: 'http://localhost:4000', allow: allowAll }).cookieName, 'ipc_session');
  assert.equal(createAuthClient({ authUrl: 'http://localhost:4000', allow: allowAll, cookieName: 'x' }).cookieName, 'x');

  const secure = createAuthClient({ authUrl: auth.url, allow: allowAll, cookieName: '__Secure-ipc_session' });
  const token = await mint(key, auth.url);
  assert.deepEqual(await secure.verifySession(cookie(token, '__Secure-ipc_session')), USER_A);
  assert.equal(await secure.verifySession(cookie(token, 'ipc_session')), null);
});

test('duplicate cookies: the first one that verifies wins', async () => {
  const good = await mint(key, auth.url);
  const header = `ipc_session=stale.bad.token; other=1; ipc_session=${good}`;
  assert.deepEqual(await client().verifySession(header), USER_A);
  assert.deepEqual(cookieValues('a=1; ipc_session="q"; b=2', 'ipc_session'), ['q']);
});

test('constructor validates its options', () => {
  assert.throws(() => createAuthClient({ authUrl: auth.url } as never), /allow/);
  assert.throws(() => createAuthClient({ authUrl: 'not a url', allow: allowAll }), /valid URL/);
  assert.throws(() => createAuthClient({ authUrl: 'https://auth.ipcharles.com/login', allow: allowAll }), /bare origin/);
  assert.ok(createAuthClient({ authUrl: 'https://auth.ipcharles.com/', allow: allowAll, baseUrl: BASE }));
});

test('JWKS is fetched once and cached across verifications', async () => {
  const fake = await startFakeAuth([key]);
  try {
    const c = createAuthClient({ authUrl: fake.url, allow: allowAll });
    const token = await mint(key, fake.url);
    await Promise.all(Array.from({ length: 20 }, () => c.verifySession(cookie(token))));
    for (let i = 0; i < 5; i++) await c.verifySession(cookie(token));
    assert.equal(fake.hits(), 1);
  } finally {
    await fake.close();
  }
});

test('JWKS refreshes after the TTL, and keeps serving stale keys if the refresh fails', async () => {
  const fake = await startFakeAuth([key]);
  let now = 1_000_000;
  try {
    const c = createAuthClient({ authUrl: fake.url, allow: allowAll, now: () => now });
    const cookieHeader = cookie(await mint(key, fake.url, USER_A, { exp: '1000d' }));
    assert.ok(await c.verifySession(cookieHeader));
    assert.equal(fake.hits(), 1);

    now += 3_599_000;
    assert.ok(await c.verifySession(cookieHeader));
    assert.equal(fake.hits(), 1, 'within the one hour TTL');

    now += 2_000;
    fake.setDown(true);
    assert.deepEqual(await c.verifySession(cookieHeader), USER_A, 'stale key still verifies while the auth service is down');
    assert.equal(fake.hits(), 2, 'TTL expired: a refresh was attempted');
    assert.ok(await c.verifySession(cookieHeader));
    assert.equal(fake.hits(), 2, 'a failed refresh is not retried inside the cooldown');

    fake.setDown(false);
    now += 31_000;
    assert.ok(await c.verifySession(cookieHeader));
    assert.equal(fake.hits(), 3, 'recovers once the service is back');
  } finally {
    await fake.close();
  }

  // Nothing cached and the service is down: verification fails closed.
  const down = await startFakeAuth([key]);
  down.setDown(true);
  const c = createAuthClient({ authUrl: down.url, allow: allowAll });
  assert.equal(await c.verifySession(cookie(await mint(key, down.url))), null);
  await down.close();
});

test('key rotation: an unknown kid triggers one refetch, so new cookies verify without waiting an hour', async () => {
  const k1 = newKey('k1');
  const k2 = newKey('k2');
  const fake = await startFakeAuth([k1]);
  let now = 5_000_000;
  try {
    const c = createAuthClient({ authUrl: fake.url, allow: allowAll, now: () => now });
    assert.ok(await c.verifySession(cookie(await mint(k1, fake.url, USER_A, { exp: '1000d' }))));
    assert.equal(fake.hits(), 1);

    fake.setKeys([k2, k1]); // gentle rotation
    const newToken = await mint(k2, fake.url, USER_A, { exp: '1000d' });
    assert.equal(await c.verifySession(cookie(newToken)), null, 'inside the cooldown, no refetch yet');
    assert.equal(fake.hits(), 1);
    now += 31_000;
    assert.deepEqual(await c.verifySession(cookie(newToken)), USER_A);
    assert.equal(fake.hits(), 2);

    // Garbage kids cannot be used to hammer the auth service.
    const junk = () => Promise.all(Array.from({ length: 10 }, async (_, i) => c.verifySession(cookie(await mint(k1, fake.url, USER_A, { kid: `junk${i}` })))));
    await junk();
    assert.equal(fake.hits(), 2, 'inside the cooldown after a refetch: no more fetches');
    now += 31_000;
    await junk();
    assert.equal(fake.hits(), 3, 'a whole burst of unknown kids costs one refetch');
  } finally {
    await fake.close();
  }
});

test('navigation vs API detection', () => {
  const h = (headers: Record<string, string>) => headers;
  assert.equal(wantsRedirect('GET', h({ accept: 'text/html,application/xhtml+xml' })), true);
  assert.equal(wantsRedirect('GET', h({ accept: 'text/html', 'sec-fetch-mode': 'navigate' })), true);
  assert.equal(wantsRedirect('GET', h({ accept: '*/*', 'sec-fetch-mode': 'cors' })), false);
  assert.equal(wantsRedirect('GET', h({ accept: 'application/json' })), false);
  assert.equal(wantsRedirect('GET', h({ accept: 'text/html, application/json' })), false);
  assert.equal(wantsRedirect('GET', h({ accept: 'text/html', 'sec-fetch-mode': 'cors' })), false, 'fetch() asking for html');
  assert.equal(wantsRedirect('POST', h({ accept: 'text/html' })), false);
  assert.equal(wantsRedirect('GET', h({})), false);
});

test('default verifySession reads AUTH_URL from the environment', async () => {
  const saved = process.env.AUTH_URL;
  delete process.env.AUTH_URL;
  assert.throws(() => verifySession(undefined), /AUTH_URL/);
  process.env.AUTH_URL = auth.url;
  try {
    assert.deepEqual(await verifySession(cookie(await mint(key, auth.url))), USER_A);
  } finally {
    if (saved === undefined) delete process.env.AUTH_URL;
    else process.env.AUTH_URL = saved;
  }
});

test('return URL cannot be redirected to another host by a crafted path', async () => {
  const c = createAuthClient({ authUrl: auth.url, allow: allowAll, baseUrl: 'https://app.ipcharles.com' });
  for (const url of ['//evil.com/x', '/\\evil.com', 'http://evil.com/', '/a?b=1']) {
    const d = await c.check({ method: 'GET', url, headers: { accept: 'text/html' }, fallbackBase: 'https://ignored.example' });
    assert.equal(d.type, 'redirect');
    if (d.type === 'redirect') {
      const returned = new URL(d.location).searchParams.get('return')!;
      assert.equal(new URL(returned).origin, 'https://app.ipcharles.com', `${url} -> ${returned}`);
    }
  }
});
