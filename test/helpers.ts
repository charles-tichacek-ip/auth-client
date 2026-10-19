import { generateKeyPairSync, type KeyObject } from 'node:crypto';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { SignJWT, exportJWK } from 'jose';

export interface TestKey {
  kid: string;
  privateKey: KeyObject;
  publicKey: KeyObject;
}

export function newKey(kid: string): TestKey {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  return { kid, privateKey, publicKey };
}

export const USER_A = { id: '11111111-1111-4111-8111-111111111111', name: 'User A' };
export const USER_B = { id: '22222222-2222-4222-8222-222222222222', name: 'User B' };

/** Mints a session token the way the auth service does. */
export function mint(
  key: TestKey,
  authUrl: string,
  user = USER_A,
  { exp = '365d', iss = authUrl, kid = key.kid }: { exp?: string | number; iss?: string; kid?: string } = {},
): Promise<string> {
  return new SignJWT({ name: user.name })
    .setProtectedHeader({ alg: 'EdDSA', kid, typ: 'JWT' })
    .setIssuer(iss)
    .setSubject(user.id)
    .setIssuedAt()
    .setExpirationTime(exp)
    .sign(key.privateKey);
}

export interface FakeAuth {
  url: string;
  /** Number of times the JWKS document was requested. */
  hits: () => number;
  setKeys(keys: TestKey[]): void;
  /** Make the JWKS endpoint answer 500 (simulates the auth service being down). */
  setDown(down: boolean): void;
  close(): Promise<void>;
}

/** A stand-in auth service that serves /.well-known/jwks.json. */
export async function startFakeAuth(initial: TestKey[]): Promise<FakeAuth> {
  let keys = initial;
  let down = false;
  let hits = 0;
  const server: Server = createServer(async (req, res) => {
    if (req.url !== '/.well-known/jwks.json') {
      res.writeHead(404).end();
      return;
    }
    hits++;
    if (down) {
      res.writeHead(500).end('down');
      return;
    }
    const body = {
      keys: await Promise.all(
        keys.map(async (k) => ({ ...(await exportJWK(k.publicKey)), kid: k.kid, alg: 'EdDSA', use: 'sig' })),
      ),
    };
    res.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify(body));
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address() as AddressInfo;
  return {
    // "localhost" so the client derives the plain dev cookie name; 127.0.0.1 would work too.
    url: `http://127.0.0.1:${port}`,
    hits: () => hits,
    setKeys: (k) => void (keys = k),
    setDown: (d) => void (down = d),
    close: () => new Promise((resolve) => server.close(() => resolve())),
  };
}

export const cookie = (token: string, name = 'ipc_session') => `${name}=${token}`;
