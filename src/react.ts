import { useCallback, useEffect, useState } from 'react';
import type { SessionUser } from './core.js';
import { parseAuthUrl } from './url.js';

let configuredAuthUrl: string | undefined;

/** Set the auth service URL once at startup, e.g. configureAuth({ authUrl: import.meta.env.VITE_AUTH_URL }). It is a public URL, not a secret. */
export function configureAuth(options: { authUrl: string }): void {
  configuredAuthUrl = parseAuthUrl(options.authUrl.replace(/\/+$/, ''));
}

function resolveAuthUrl(authUrl: string | undefined): string {
  const raw = (authUrl ?? configuredAuthUrl)?.replace(/\/+$/, '');
  if (!raw) throw new Error('@ipcharles/auth-client: call configureAuth({ authUrl }) or pass { authUrl } to useUser');
  return parseAuthUrl(raw);
}

/** Address of the auth service's sign-in page, returning to `returnTo` (default: this page). */
export function loginUrl(returnTo: string = globalThis.location?.href ?? '/', authUrl?: string): string {
  return `${resolveAuthUrl(authUrl)}/login?return=${encodeURIComponent(returnTo)}`;
}

/** Address of the auth service's account page (passkeys, sign out). */
export function accountUrl(authUrl?: string): string {
  return `${resolveAuthUrl(authUrl)}/account`;
}

/** One `GET {authUrl}/me` with credentials. Null when signed out. Throws on network or server errors. */
export async function fetchUser(authUrl: string, fetchImpl: typeof fetch = fetch): Promise<SessionUser | null> {
  const res = await fetchImpl(`${authUrl}/me`, { credentials: 'include', headers: { accept: 'application/json' } });
  if (res.status === 401) return null;
  if (!res.ok) throw new Error(`auth service answered ${res.status}`);
  const body = (await res.json()) as Partial<SessionUser>;
  if (typeof body.id !== 'string' || typeof body.name !== 'string') throw new Error('unexpected /me response');
  return { id: body.id, name: body.name };
}

export interface UseUserResult {
  user: SessionUser | null;
  loading: boolean;
  /** Set when the auth service could not be reached; `user` is null in that case. */
  error: Error | null;
  refresh: () => void;
}

export function useUser(options: { authUrl?: string } = {}): UseUserResult {
  const authUrl = resolveAuthUrl(options.authUrl);
  const [state, setState] = useState<{ user: SessionUser | null; loading: boolean; error: Error | null }>({
    user: null,
    loading: true,
    error: null,
  });
  const [tick, setTick] = useState(0);

  useEffect(() => {
    let cancelled = false;
    setState((s) => ({ ...s, loading: true }));
    fetchUser(authUrl).then(
      (user) => !cancelled && setState({ user, loading: false, error: null }),
      (error: unknown) =>
        !cancelled && setState({ user: null, loading: false, error: error instanceof Error ? error : new Error(String(error)) }),
    );
    return () => {
      cancelled = true;
    };
  }, [authUrl, tick]);

  const refresh = useCallback(() => setTick((t) => t + 1), []);
  return { ...state, refresh };
}

export type { SessionUser };
