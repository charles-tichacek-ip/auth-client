# @ipcharles/auth-client

Verify the `auth.ipcharles.com` session cookie inside an app, locally, with no network call per request. Public repo: it contains no secrets. Runtime dependency: `jose` only.

- **Fastify 5** plugin, **Express** middleware, a framework-agnostic `verifySession`, and a **React** hook.
- Checks the Ed25519 signature against the auth service's cached JWKS, plus `iss` and `exp`.
- The app's own `allow` function decides who may use it. Being signed in is not enough.
- Fastify 5 is the supported version. (Fastify 4 is end-of-life with open high-severity advisories, so it is not supported.)

## Install

```json
"@ipcharles/auth-client": "github:charles-tichacek-ip/auth-client#v0.1.0"
```

`dist/` is committed, so there is no build step on install and no token is needed.

Entry points (separate so a server app never loads React and vice versa):

| Import | Contents |
| --- | --- |
| `@ipcharles/auth-client` | `createAuthClient`, `verifySession` |
| `@ipcharles/auth-client/fastify` | `authPlugin` |
| `@ipcharles/auth-client/express` | `authMiddleware` |
| `@ipcharles/auth-client/react` | `useUser`, `configureAuth`, `loginUrl`, `accountUrl` |

## Fastify 5

```ts
import { authPlugin } from '@ipcharles/auth-client/fastify';

const ALLOWED_IDS = new Set((process.env.ALLOWED_USER_IDS ?? '').split(',').filter(Boolean));

await app.register(authPlugin, {
  authUrl: process.env.AUTH_URL!,               // https://auth.ipcharles.com
  allow: (user) => ALLOWED_IDS.has(user.id),    // required
  baseUrl: 'https://api.ipcharles.com',     // this app's public URL (required outside localhost)
  origins: ['https://app.ipcharles.com'],       // who may send POST/PUT/PATCH/DELETE (see below)
  publicPaths: ['/healthz'],
});

app.get('/reports', async (request) => ({ hello: request.user!.name }));
```

Every route registered on the same instance after the plugin is protected, and `request.user` is `{ id, name }`. To protect only some routes, register the plugin inside an encapsulated scope (`app.register(async (scope) => { await scope.register(authPlugin, …); scope.get(…) })`). Mark a single route open with `{ config: { public: true } }`. On open routes `request.user` is still set when a valid session is present, and is `null` otherwise.

## Express

```ts
import { authMiddleware } from '@ipcharles/auth-client/express';

app.use(authMiddleware({ authUrl, allow: (u) => ALLOWED_IDS.has(u.id), baseUrl, origins }));
app.get('/me', (req, res) => res.json(req.user));
```

## Anything else

```ts
import { createAuthClient } from '@ipcharles/auth-client';

const auth = createAuthClient({ authUrl, allow });
const user = await auth.verifySession(request.headers.cookie); // { id, name } | null
```

With only `AUTH_URL` set, `verifySession(cookieHeader)` works as a bare function too.

## React

```tsx
import { configureAuth, useUser, loginUrl, accountUrl } from '@ipcharles/auth-client/react';

configureAuth({ authUrl: import.meta.env.VITE_AUTH_URL }); // a public URL, safe to expose

function Header() {
  const { user, loading, error } = useUser();
  if (loading) return null;
  if (!user) return <a href={loginUrl()}>Sign in</a>;
  return <a href={accountUrl()}>{user.name}</a>;
}
```

`useUser` calls `GET {authUrl}/me` with `credentials: 'include'`. `error` is set (and `user` is null) if the auth service is unreachable; `refresh()` re-checks. Sign-out happens on the auth service's account page, because its `POST /logout` only accepts its own origin.

## What happens to a request

| Situation | Result |
| --- | --- |
| Valid cookie, `allow` says yes | Request continues; `request.user` / `req.user` is set |
| Valid cookie, `allow` says no | **403** `{"error":"forbidden"}` |
| No or invalid cookie, browser page load (`Accept: text/html`, or `Sec-Fetch-Mode: navigate`) | **302** to `{authUrl}/login?return=<this URL>` |
| No or invalid cookie, `fetch`/XHR (`Accept: application/json`, `Sec-Fetch-Mode: cors`, or non-GET) | **401** `{"error":"unauthenticated"}` |
| POST/PUT/PATCH/DELETE with a missing or non-allowed `Origin` | **403** `{"error":"bad_origin"}` (checked before authentication) |
| `OPTIONS` | Passed through, so CORS preflights reach your CORS handler |

### Options

| Option | Notes |
| --- | --- |
| `authUrl` | Required. Bare https origin, e.g. `https://auth.ipcharles.com` (plain http only for localhost, e.g. `http://localhost:4000`). Also the expected `iss`. |
| `allow(user)` | Required, may be async. Must return exactly `true` to admit the user; anything else, or a throw, denies. |
| `baseUrl` | **Required** unless `authUrl` is on localhost. This app's public URL (an https bare origin). It anchors the sign-in `return` address and the default `Origin` check, so a forged `Host` header cannot widen either. |
| `origins` | Allowed `Origin` values for state-changing requests. Defaults to the app's own origin. |
| `allowMissingOrigin` | Default `false`. Browsers always send `Origin` on these requests; set `true` only for non-browser callers. A present but wrong `Origin` still fails. |
| `publicPaths` | Exact paths served without authentication, e.g. `/healthz`. |
| `cookieName` | Default `__Secure-ipc_session` for an https `authUrl`, `ipc_session` for http (dev). |

## Security properties

See [SECURITY.md](SECURITY.md) for the full list and how to report a problem. In short: EdDSA only, issuer/expiry/`kid` required, no header-supplied keys, https-only auth URL, size-capped redirect-free JWKS fetch, strict `allow() === true`, and CI that fails if the committed `dist/` differs from a clean build.

## Why the Origin check exists

`SameSite=Lax` keeps other sites from riding the cookie, but not other subdomains of `ipcharles.com`, which are same-site. Checking `Origin` on state-changing requests closes that gap. This is on by default.

## Front end and API on different subdomains (app and api)

The cookie reaches both hosts. The front end must call the API with `credentials: 'include'`, and the API needs CORS with an explicit origin and credentials (never `*`):

```ts
await app.register(cors, { origin: ['https://app.ipcharles.com'], credentials: true });
await app.register(authPlugin, { …, origins: ['https://app.ipcharles.com'] });
```

Register `@fastify/cors` before the plugin or after it; the plugin lets `OPTIONS` preflights through.

## Keys, rotation and outages

- Public keys come from `{authUrl}/.well-known/jwks.json`, cached for an hour.
- An unknown `kid` triggers one refetch (at most once every 30 seconds), so a gently rotated key is picked up immediately and junk key ids cannot hammer the auth service.
- If the auth service is down, the cached keys keep working. With nothing cached, verification fails closed.
- After a hard rotation (old public key dropped), old cookies fail as soon as the app refetches, within the hour at most.
- Existing sessions stay valid until their cookie expires or the key is rotated: there is no per-request revocation. A user disabled in the auth service keeps access to apps until then.

## Development

```bash
npm install
npm test         # real Fastify 5 and Express apps against a fake auth service
npm run typecheck
```

Locally, point apps at `AUTH_URL=http://localhost:4000`; the package then reads the host-only `ipc_session` cookie.

### Releasing

`dist/` is committed so consumers need no build. Cut a release with:

```bash
npm version patch   # runs typecheck and tests, rebuilds dist/, commits it, and tags vX.Y.Z
git push --follow-tags
```

Then bump the `#vX.Y.Z` in each app's dependency.
