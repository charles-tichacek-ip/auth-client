import { useCallback, useEffect, useState } from 'react';
import { parseAuthUrl } from './url.js';
let configuredAuthUrl;
/** Set the auth service URL once at startup, e.g. configureAuth({ authUrl: import.meta.env.VITE_AUTH_URL }). It is a public URL, not a secret. */
export function configureAuth(options) {
    configuredAuthUrl = parseAuthUrl(options.authUrl.replace(/\/+$/, ''));
}
function resolveAuthUrl(authUrl) {
    const raw = (authUrl ?? configuredAuthUrl)?.replace(/\/+$/, '');
    if (!raw)
        throw new Error('@ipcharles/auth-client: call configureAuth({ authUrl }) or pass { authUrl } to useUser');
    return parseAuthUrl(raw);
}
/** Address of the auth service's sign-in page, returning to `returnTo` (default: this page). */
export function loginUrl(returnTo = globalThis.location?.href ?? '/', authUrl) {
    return `${resolveAuthUrl(authUrl)}/login?return=${encodeURIComponent(returnTo)}`;
}
/** Address of the auth service's account page (passkeys, sign out). */
export function accountUrl(authUrl) {
    return `${resolveAuthUrl(authUrl)}/account`;
}
/** One `GET {authUrl}/me` with credentials. Null when signed out. Throws on network or server errors. */
export async function fetchUser(authUrl, fetchImpl = fetch) {
    const res = await fetchImpl(`${authUrl}/me`, { credentials: 'include', headers: { accept: 'application/json' } });
    if (res.status === 401)
        return null;
    if (!res.ok)
        throw new Error(`auth service answered ${res.status}`);
    const body = (await res.json());
    if (typeof body.id !== 'string' || typeof body.name !== 'string')
        throw new Error('unexpected /me response');
    return { id: body.id, name: body.name };
}
export function useUser(options = {}) {
    const authUrl = resolveAuthUrl(options.authUrl);
    const [state, setState] = useState({
        user: null,
        loading: true,
        error: null,
    });
    const [tick, setTick] = useState(0);
    useEffect(() => {
        let cancelled = false;
        setState((s) => ({ ...s, loading: true }));
        fetchUser(authUrl).then((user) => !cancelled && setState({ user, loading: false, error: null }), (error) => !cancelled && setState({ user: null, loading: false, error: error instanceof Error ? error : new Error(String(error)) }));
        return () => {
            cancelled = true;
        };
    }, [authUrl, tick]);
    const refresh = useCallback(() => setTick((t) => t + 1), []);
    return { ...state, refresh };
}
