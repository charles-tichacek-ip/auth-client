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
export type Decision = {
    type: 'ok';
    user: SessionUser;
} | {
    type: 'public';
    user: SessionUser | null;
} | {
    type: 'redirect';
    location: string;
} | {
    type: 'unauthenticated';
} | {
    type: 'forbidden';
    user: SessionUser;
} | {
    type: 'bad_origin';
};
/** Browser page loads get a redirect to sign in; fetch/XHR callers get a 401. */
export declare function wantsRedirect(method: string, headers: RequestInfo['headers']): boolean;
export declare function createAuthClient(options: AuthClientOptions): {
    verifySession: (cookieHeader: string | undefined) => Promise<SessionUser | null>;
    check: (req: RequestInfo) => Promise<Decision>;
    loginUrl: (returnTo: string) => string;
    authUrl: string;
    cookieName: string;
};
export type AuthClient = ReturnType<typeof createAuthClient>;
/**
 * Framework-agnostic helper: verifies a Cookie header against the auth service named by
 * the AUTH_URL environment variable. Use `createAuthClient` for anything beyond that.
 */
export declare function verifySession(cookieHeader: string | undefined): Promise<SessionUser | null>;
