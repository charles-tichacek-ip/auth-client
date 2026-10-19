import { jwtVerify } from 'jose';
import { cookieValues } from './cookies.js';
import { createJwksCache } from './jwks.js';
import { isLoopbackHost, parseAuthUrl } from './url.js';

export interface SessionUser {
  id: string;
  name: string;
}

export interface AuthClientOptions {
  /** Base URL of the auth service, e.g. https://auth.ipcharles.com (dev: http://localhost:4000). */
  authUrl: string;
  /** Per-app access rule. Required: being signed in is not the same as being allowed in. */
  allow: (user: SessionUser) => boolean | Promise<boolean>;
  /**
   * Origins allowed on state-changing requests (POST, PUT, PATCH, DELETE).
   * Set this when the front end is on a different subdomain than the API,
   * e.g. ['https://app.ipcharles.com']. Defaults to this app's own origin.
   */
  origins?: string[];
  /**
   * This app's public base URL, e.g. https://api.ipcharles.com. Required unless authUrl is on localhost.
   * It anchors the `return` address and the default Origin check, so neither depends on the Host header.
   */
  baseUrl?: string;
  /** Accept state-changing requests that carry no Origin header (non-browser callers). Default false. */
  allowMissingOrigin?: boolean;
  /** Exact paths served without authentication (e.g. '/healthz'). The user is still attached when a valid cookie is present. */
  publicPaths?: string[];
  /** Override the cookie name. Derived from authUrl by default. */
  cookieName?: string;
  /** Test hooks. */
  fetch?: typeof fetch;
  now?: () => number;
}

export interface RequestInfo {
  method: string;
  /** Path and query, as received. */
  url: string;
  headers: Record<string, string | string[] | undefined>;
  /** Origin to assume for this app when `baseUrl` is not configured, e.g. "https://app.ipcharles.com". */
  fallbackBase: string;
}

export type Decision =
  | { type: 'ok'; user: SessionUser }
  | { type: 'public'; user: SessionUser | null }
  | { type: 'redirect'; location: string }
  | { type: 'unauthenticated' }
  | { type: 'forbidden'; user: SessionUser }
  | { type: 'bad_origin' };

/** Real session tokens are well under 400 bytes; refuse to parse anything absurd. */
const MAX_TOKEN_LENGTH = 4096;
const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

function header(headers: RequestInfo['headers'], name: string): string | undefined {
  const value = headers[name];
  return Array.isArray(value) ? value.join(', ') : value;
}

/** Browser page loads get a redirect to sign in; fetch/XHR callers get a 401. */
export function wantsRedirect(method: string, headers: RequestInfo['headers']): boolean {
  if (method !== 'GET' && method !== 'HEAD') return false;
  const accept = header(headers, 'accept') ?? '';
  if (accept.includes('application/json')) return false;
  const mode = header(headers, 'sec-fetch-mode');
  if (mode) return mode === 'navigate';
  return accept.includes('text/html');
}

export function createAuthClient(options: AuthClientOptions) {
  if (typeof options.allow !== 'function') {
    throw new Error('@ipcharles/auth-client: the `allow` option is required');
  }
  const auth = new URL(parseAuthUrl(options.authUrl));
  const authOrigin = auth.origin;
  if (!options.baseUrl && !isLoopbackHost(auth.hostname)) {
    throw new Error(
      '@ipcharles/auth-client: `baseUrl` is required (this app\'s public URL, e.g. https://api.ipcharles.com). ' +
        'Deriving it from the Host header would let a forged Host defeat the Origin check.',
    );
  }
  const baseOrigin = options.baseUrl === undefined ? undefined : parseAuthUrl(options.baseUrl, 'baseUrl').toString();
  const allowedOrigins = options.origins?.map((o) => parseAuthUrl(o, 'origins entry'));
  const cookieName = options.cookieName ?? (auth.protocol === 'https:' ? '__Secure-ipc_session' : 'ipc_session');
  const publicPaths = new Set(options.publicPaths ?? []);
  const jwksKey = createJwksCache({
    url: `${authOrigin}/.well-known/jwks.json`,
    fetch: options.fetch,
    now: options.now,
  });

  // Only a key id we know may select a key. Header-supplied keys (jwk, jku, x5u, x5c) are refused outright.
  const getKey: typeof jwksKey = (header, token) => {
    if (typeof header.kid !== 'string' || 'jwk' in header || 'jku' in header || 'x5u' in header || 'x5c' in header) {
      throw new Error('unacceptable token header');
    }
    return jwksKey(header, token);
  };

  /** The signed-in user for a Cookie header, or null. Pure signature, issuer and expiry check: no network call except JWKS refreshes. */
  async function verifySession(cookieHeader: string | undefined): Promise<SessionUser | null> {
    for (const token of cookieValues(cookieHeader, cookieName)) {
      if (token.length > MAX_TOKEN_LENGTH) continue;
      try {
        const { payload } = await jwtVerify(token, getKey, {
          algorithms: ['EdDSA'],
          issuer: authOrigin,
          requiredClaims: ['sub', 'exp'],
          // The `now` hook is for tests: jose reads time from currentDate.
          ...(options.now ? { currentDate: new Date(options.now()) } : {}),
        });
        if (typeof payload.sub === 'string' && typeof payload.name === 'string') {
          return { id: payload.sub, name: payload.name };
        }
      } catch {
        // Try the next cookie with this name, if any.
      }
    }
    return null;
  }

  function loginUrl(returnTo: string): string {
    return `${authOrigin}/login?return=${encodeURIComponent(returnTo)}`;
  }

  /** The whole policy for one request. Framework adapters only translate the result. */
  async function check(req: RequestInfo): Promise<Decision> {
    const base = baseOrigin ?? req.fallbackBase;
    const path = req.url.split('?')[0] ?? req.url;
    const method = req.method.toUpperCase();

    if (publicPaths.has(path)) {
      return { type: 'public', user: await verifySession(header(req.headers, 'cookie')) };
    }

    if (!SAFE_METHODS.has(method)) {
      const origin = header(req.headers, 'origin');
      const allowed = allowedOrigins ?? [new URL(base).origin];
      const ok = origin === undefined ? options.allowMissingOrigin === true : allowed.includes(origin);
      if (!ok) return { type: 'bad_origin' };
    }

    const user = await verifySession(header(req.headers, 'cookie'));
    if (!user) {
      if (wantsRedirect(method, req.headers)) {
        // Concatenate rather than resolve: a request path like "//evil.com/x" must not change the host.
        const target = new URL(base).origin + (req.url.startsWith('/') ? req.url : '/');
        return { type: 'redirect', location: loginUrl(target) };
      }
      return { type: 'unauthenticated' };
    }
    // Strict: only a literal `true` admits the user, so a sloppy `allow` returning a string or object fails closed.
    if ((await options.allow(user)) !== true) return { type: 'forbidden', user };
    return { type: 'ok', user };
  }

  return { verifySession, check, loginUrl, authUrl: authOrigin, cookieName };
}

export type AuthClient = ReturnType<typeof createAuthClient>;

let defaultClient: AuthClient | undefined;

/**
 * Framework-agnostic helper: verifies a Cookie header against the auth service named by
 * the AUTH_URL environment variable. Use `createAuthClient` for anything beyond that.
 */
export function verifySession(cookieHeader: string | undefined): Promise<SessionUser | null> {
  if (!defaultClient) {
    const authUrl = process.env.AUTH_URL;
    if (!authUrl) throw new Error('@ipcharles/auth-client: set AUTH_URL or use createAuthClient()');
    defaultClient = createAuthClient({ authUrl, allow: () => true });
  }
  return defaultClient.verifySession(cookieHeader);
}
