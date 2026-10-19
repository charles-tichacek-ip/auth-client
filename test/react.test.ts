import assert from 'node:assert/strict';
import { test } from 'node:test';
import { accountUrl, configureAuth, fetchUser, loginUrl } from '../src/react.js';

const reply = (status: number, body?: unknown) => async () => new Response(body === undefined ? null : JSON.stringify(body), { status });

test('fetchUser: 200 gives the user, 401 gives null, anything else throws', async () => {
  assert.deepEqual(await fetchUser('https://a', reply(200, { id: 'u', name: 'N' }) as never), { id: 'u', name: 'N' });
  assert.equal(await fetchUser('https://a', reply(401, { error: 'unauthenticated' }) as never), null);
  await assert.rejects(fetchUser('https://a', reply(500) as never), /500/);
  await assert.rejects(fetchUser('https://a', reply(200, { nope: 1 }) as never), /unexpected/);
});

test('fetchUser sends credentials to {authUrl}/me', async () => {
  let seen: { url: string; init?: RequestInit } | undefined;
  await fetchUser('https://auth.ipcharles.com', (async (url: string, init?: RequestInit) => {
    seen = { url, init };
    return new Response(JSON.stringify({ id: 'u', name: 'N' }));
  }) as never);
  assert.equal(seen?.url, 'https://auth.ipcharles.com/me');
  assert.equal(seen?.init?.credentials, 'include');
});

test('loginUrl and accountUrl build auth service addresses', () => {
  configureAuth({ authUrl: 'https://auth.ipcharles.com/' });
  assert.equal(loginUrl('https://app.ipcharles.com/x?y=1'), 'https://auth.ipcharles.com/login?return=https%3A%2F%2Fapp.ipcharles.com%2Fx%3Fy%3D1');
  assert.equal(accountUrl(), 'https://auth.ipcharles.com/account');
  assert.equal(accountUrl('http://localhost:4000'), 'http://localhost:4000/account');
});
