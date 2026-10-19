/** Hosts where plain http is acceptable: local development only. */
export function isLoopbackHost(hostname) {
    return hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '[::1]' || hostname.endsWith('.localhost');
}
/**
 * Parses the auth service URL and refuses anything that could leak the session or
 * the signing keys: non-bare origins, embedded credentials, and plain http outside loopback.
 * Returns the normalized origin.
 */
export function parseAuthUrl(raw, label = 'authUrl') {
    let url;
    try {
        url = new URL(String(raw));
    }
    catch {
        throw new Error(`@ipcharles/auth-client: ${label} is not a valid URL`);
    }
    if (url.pathname !== '/' || url.search || url.hash) {
        throw new Error(`@ipcharles/auth-client: ${label} must be a bare origin like https://auth.ipcharles.com`);
    }
    if (url.username || url.password) {
        throw new Error(`@ipcharles/auth-client: ${label} must not contain credentials`);
    }
    if (url.protocol !== 'https:' && !(url.protocol === 'http:' && isLoopbackHost(url.hostname))) {
        throw new Error(`@ipcharles/auth-client: ${label} must use https (http is only allowed for localhost)`);
    }
    return url.origin;
}
