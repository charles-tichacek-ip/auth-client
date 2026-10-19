import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import { generateKeyPairSync } from 'node:crypto';
import { after, before, test } from 'node:test';
import { SignJWT, exportJWK } from 'jose';
import Fastify from 'fastify';
import { createAuthClient } from '../src/index.js';
import { authPlugin } from '../src/fastify.js';
import { accountUrl, configureAuth, loginUrl } from '../src/react.js';
import { USER_A, cookie, mint, newKey, startFakeAuth, type FakeAuth } from './helpers.js';

const key = newKey('k1');
let auth: FakeAuth;
const allowAll = () => true;
const BASE = 'https://app.ipcharles.com';

before(async () => {
  auth = await startFakeAuth([key]);
});
after(() => auth.close());

// ---- configuration is refused when it would be unsafe ----

test('authUrl must be https, except on loopback, with no credentials or path', () => {
  const make = (authUrl: string, extra = {}) => () => createAuthClient({ authUrl, allow: allowAll, baseUrl: BASE, ...extra });
  assert.throws(make('http://auth.ipcharles.com'), /https/);
  assert.throws(make('http://evil.example'), /https/);
  assert.throws(make('ftp://auth.ipcharles.com'), /https/);
  assert.throws(make('https://user:pw@auth.ipcharles.com'), /credentials/);
  assert.throws(make('https://auth.ipcharles.com/login'), /bare origin/);
  assert.throws(make('https://auth.ipcharles.com/?x=1'), /bare origin/);
  assert.throws(make('http://localhost.evil.com'), /https/, 'a hostname that merely starts with localhost');
  for (const ok of ['https://auth.ipcharles.com', 'http://localhost:4000', 'http://127.0.0.1:4000', 'http://[::1]:4000']) {
    assert.ok(make(ok)(), ok);
  }
});

test('baseUrl is required off-loopback so the Host header never decides trust', () => {
  assert.throws(() => createAuthClient({ authUrl: 'https://auth.ipcharles.com', allow: allowAll }), /baseUrl/);
  assert.ok(createAuthClient({ authUrl: 'http://localhost:4000', allow: allowAll }), 'fine for local development');
  assert.throws(() => createAuthClient({ authUrl: 'https://auth.ipcharles.com', allow: allowAll, baseUrl: 'http://app.ipcharles.com' }), /https/);
  assert.throws(() => createAuthClient({ authUrl: 'https://auth.ipcharles.com', allow: allowAll, baseUrl: BASE, origins: ['not a url'] }), /origins/);
  assert.throws(() => createAuthClient({ authUrl: 'https://auth.ipcharles.com', allow: allowAll, baseUrl: BASE, origins: ['http://app.ipcharles.com'] }), /https/);
});

test('a forged Host header cannot widen the Origin check or the return address', async () => {
  const app = Fastify();
  await app.register(authPlugin, { authUrl: auth.url, allow: allowAll, baseUrl: BASE });
  app.post('/things', async () => ({ ok: true }));
  app.get('/page', async () => ({ ok: true }));
  const token = cookie(await mint(key, auth.url));

  const post = await app.inject({ method: 'POST', url: '/things', headers: { host: 'evil.example', origin: 'https://evil.example', cookie: token, accept: 'application/json' } });
  assert.equal(post.statusCode, 403, 'Origin must match baseUrl, not Host');

  const nav = await app.inject({ url: '/page', headers: { host: 'evil.example', accept: 'text/html', 'sec-fetch-mode': 'navigate' } });
  assert.equal(new URL(nav.headers.location as string).searchParams.get('return'), `${BASE}/page`);
});

test('the browser hook applies the same URL rules', () => {
  assert.throws(() => configureAuth({ authUrl: 'http://auth.ipcharles.com' }), /https/);
  assert.throws(() => accountUrl('http://evil.example'), /https/);
  assert.throws(() => loginUrl('/x', 'https://u:p@auth.ipcharles.com'), /credentials/);
});

// ---- token attacks ----

test('algorithm confusion and non-EdDSA signatures are rejected', async () => {
  const c = createAuthClient({ authUrl: auth.url, allow: allowAll });
  const ec = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const rsa = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const sign = (alg: string, k: never) =>
    new SignJWT({ name: 'X' }).setProtectedHeader({ alg, kid: 'k1' }).setIssuer(auth.url).setSubject('u').setExpirationTime('1h').sign(k);
  assert.equal(await c.verifySession(cookie(await sign('ES256', ec.privateKey as never))), null);
  assert.equal(await c.verifySession(cookie(await sign('RS256', rsa.privateKey as never))), null);
  // HS256 using the *public* key bytes as the HMAC secret (the classic downgrade).
  const jwk = await exportJWK(key.publicKey);
  assert.equal(await c.verifySession(cookie(await sign('HS256', new TextEncoder().encode(jwk.x!) as never))), null);
});

test('header-supplied keys (jwk, jku, x5u, x5c) are never used', async () => {
  const hits: string[] = [];
  const attackerKey = newKey('k1');
  const attacker = createServer(async (req, res) => {
    hits.push(req.url ?? '');
    const jwk = { ...(await exportJWK(attackerKey.publicKey)), kid: 'k1', alg: 'EdDSA' };
    res.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify({ keys: [jwk] }));
  });
  await new Promise<void>((r) => attacker.listen(0, '127.0.0.1', r));
  const attackerUrl = `http://127.0.0.1:${(attacker.address() as AddressInfo).port}/jwks`;
  try {
    const c = createAuthClient({ authUrl: auth.url, allow: allowAll });
    const attackerPublic = { ...(await exportJWK(attackerKey.publicKey)), kid: 'k1' };
    for (const extra of [{ jwk: attackerPublic }, { jku: attackerUrl }, { x5u: attackerUrl }, { x5c: ['AAAA'] }]) {
      const token = await new SignJWT({ name: 'Evil' })
        .setProtectedHeader({ alg: 'EdDSA', kid: 'k1', ...extra })
        .setIssuer(auth.url)
        .setSubject('attacker')
        .setExpirationTime('1h')
        .sign(attackerKey.privateKey);
      assert.equal(await c.verifySession(cookie(token)), null, JSON.stringify(Object.keys(extra)));
    }
    assert.deepEqual(hits, [], 'the client never contacted a URL named inside a token');
  } finally {
    await new Promise<void>((r) => attacker.close(() => r()));
  }
});

test('a token without a kid, with a missing name or sub, or from the future is rejected', async () => {
  const c = createAuthClient({ authUrl: auth.url, allow: allowAll });
  const base = (header: Record<string, unknown>, claims: Record<string, unknown>, sub: string | null = 'u') => {
    const jwt = new SignJWT(claims).setProtectedHeader({ alg: 'EdDSA', ...header }).setIssuer(auth.url).setExpirationTime('1h');
    if (sub !== null) jwt.setSubject(sub);
    return jwt;
  };
  assert.ok(await c.verifySession(cookie(await base({ kid: 'k1' }, { name: 'ok' }).sign(key.privateKey))), 'control');
  assert.equal(await c.verifySession(cookie(await base({}, { name: 'x' }).sign(key.privateKey))), null, 'no kid');
  assert.equal(await c.verifySession(cookie(await base({ kid: 'k1' }, {}).sign(key.privateKey))), null, 'no name');
  assert.equal(await c.verifySession(cookie(await base({ kid: 'k1' }, { name: 5 }).sign(key.privateKey))), null, 'name not a string');
  assert.equal(await c.verifySession(cookie(await base({ kid: 'k1' }, { name: 'x' }, null).sign(key.privateKey))), null, 'no sub');
  const future = await base({ kid: 'k1' }, { name: 'x', nbf: Math.floor(Date.now() / 1000) + 3600 }).sign(key.privateKey);
  assert.equal(await c.verifySession(cookie(future)), null, 'not yet valid');
});

test('oversized tokens are not parsed, and duplicate cookies cannot force many verifications', async () => {
  const c = createAuthClient({ authUrl: auth.url, allow: allowAll });
  const good = await mint(key, auth.url);
  assert.equal(await c.verifySession(cookie('a'.repeat(5000))), null);
  assert.equal(await c.verifySession(cookie(good + '.' + 'a'.repeat(5000))), null);
  // Five junk candidates fill the cap, so a valid sixth is ignored. Real browsers send one or two.
  const junk = Array.from({ length: 5 }, () => 'ipc_session=x.y.z').join('; ');
  assert.equal(await c.verifySession(`${junk}; ipc_session=${good}`), null);
  assert.ok(await c.verifySession(`ipc_session=x.y.z; ipc_session=${good}`));
});

// ---- the JWKS channel ----

async function jwksServer(handler: (req: import('node:http').IncomingMessage, res: import('node:http').ServerResponse) => void) {
  const server = createServer(handler);
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  return { url: `http://127.0.0.1:${(server.address() as AddressInfo).port}`, close: () => new Promise<void>((r) => server.close(() => r())) };
}

test('JWKS: redirects, oversized, malformed and non-Ed25519 documents are refused (fail closed)', async () => {
  const goodJwk = { ...(await exportJWK(key.publicKey)), kid: 'k1', alg: 'EdDSA' };
  const rsaJwk = { ...(await exportJWK(generateKeyPairSync('rsa', { modulusLength: 2048 }).publicKey)), kid: 'k1' };
  const cases: Record<string, (res: import('node:http').ServerResponse) => void> = {
    redirect: (res) => res.writeHead(302, { location: 'https://evil.example/jwks' }).end(),
    huge: (res) => res.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify({ keys: [goodJwk], pad: 'x'.repeat(200_000) })),
    notJson: (res) => res.writeHead(200).end('<html>nope</html>'),
    noKeys: (res) => res.writeHead(200).end(JSON.stringify({ keys: 'nope' })),
    tooMany: (res) => res.writeHead(200).end(JSON.stringify({ keys: Array.from({ length: 21 }, (_, i) => ({ ...goodJwk, kid: `k${i}` })) })),
    wrongType: (res) => res.writeHead(200).end(JSON.stringify({ keys: [rsaJwk] })),
  };
  for (const [name, respond] of Object.entries(cases)) {
    const srv = await jwksServer((_req, res) => respond(res));
    try {
      const c = createAuthClient({ authUrl: srv.url, allow: allowAll });
      assert.equal(await c.verifySession(cookie(await mint(key, srv.url))), null, name);
    } finally {
      await srv.close();
    }
  }
});

test('JWKS: only Ed25519 keys with a kid survive filtering', async () => {
  const goodJwk = { ...(await exportJWK(key.publicKey)), kid: 'k1', alg: 'EdDSA' };
  const rsaJwk = { ...(await exportJWK(generateKeyPairSync('rsa', { modulusLength: 2048 }).publicKey)), kid: 'rsa' };
  const noKid = { ...(await exportJWK(newKey('x').publicKey)) };
  const srv = await jwksServer((_req, res) => void res.writeHead(200).end(JSON.stringify({ keys: [rsaJwk, noKid, goodJwk] })));
  try {
    const c = createAuthClient({ authUrl: srv.url, allow: allowAll });
    assert.deepEqual((await c.verifySession(cookie(await mint(key, srv.url))))?.id, USER_A.id);
  } finally {
    await srv.close();
  }
});

// ---- authorization fails closed ----

test('an allow() that throws never lets the request through', async () => {
  const app = Fastify();
  await app.register(authPlugin, {
    authUrl: auth.url,
    baseUrl: BASE,
    allow: () => {
      throw new Error('database is down');
    },
  });
  let reached = false;
  app.get('/page', async () => {
    reached = true;
    return { secret: true };
  });
  const res = await app.inject({ url: '/page', headers: { accept: 'application/json', cookie: cookie(await mint(key, auth.url)) } });
  assert.equal(res.statusCode, 500);
  assert.equal(reached, false);
  assert.doesNotMatch(res.body, /secret/);
});

test('allow() must return true: truthy non-booleans are not enough', async () => {
  const app = Fastify();
  await app.register(authPlugin, { authUrl: auth.url, baseUrl: BASE, allow: (() => 'yes') as never });
  app.get('/page', async () => ({ ok: true }));
  const res = await app.inject({ url: '/page', headers: { accept: 'application/json', cookie: cookie(await mint(key, auth.url)) } });
  assert.equal(res.statusCode, 403);
});
