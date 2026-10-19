/** Hosts where plain http is acceptable: local development only. */
export declare function isLoopbackHost(hostname: string): boolean;
/**
 * Parses the auth service URL and refuses anything that could leak the session or
 * the signing keys: non-bare origins, embedded credentials, and plain http outside loopback.
 * Returns the normalized origin.
 */
export declare function parseAuthUrl(raw: unknown, label?: string): string;
