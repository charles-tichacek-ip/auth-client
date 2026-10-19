import { type JWTVerifyGetKey } from 'jose';
export interface JwksCacheOptions {
    /** Full URL of the JWKS document. */
    url: string;
    /** How long fetched keys are trusted before a refresh is attempted. Default one hour. */
    ttlMs?: number;
    /** Minimum gap between refetches triggered by an unknown key id. Default 30 seconds. */
    cooldownMs?: number;
    fetch?: typeof fetch;
    now?: () => number;
}
/**
 * Cached JWKS with two behaviours a plain remote key set lacks:
 * - keys survive the auth service being down (stale keys are served on a failed refresh);
 * - an unknown `kid` triggers one refetch (rate limited), so key rotation is picked up at once.
 */
export declare function createJwksCache(options: JwksCacheOptions): JWTVerifyGetKey;
