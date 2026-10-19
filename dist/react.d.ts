import type { SessionUser } from './core.js';
/** Set the auth service URL once at startup, e.g. configureAuth({ authUrl: import.meta.env.VITE_AUTH_URL }). It is a public URL, not a secret. */
export declare function configureAuth(options: {
    authUrl: string;
}): void;
/** Address of the auth service's sign-in page, returning to `returnTo` (default: this page). */
export declare function loginUrl(returnTo?: string, authUrl?: string): string;
/** Address of the auth service's account page (passkeys, sign out). */
export declare function accountUrl(authUrl?: string): string;
/** One `GET {authUrl}/me` with credentials. Null when signed out. Throws on network or server errors. */
export declare function fetchUser(authUrl: string, fetchImpl?: typeof fetch): Promise<SessionUser | null>;
export interface UseUserResult {
    user: SessionUser | null;
    loading: boolean;
    /** Set when the auth service could not be reached; `user` is null in that case. */
    error: Error | null;
    refresh: () => void;
}
export declare function useUser(options?: {
    authUrl?: string;
}): UseUserResult;
export type { SessionUser };
