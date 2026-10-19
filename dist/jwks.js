import { createLocalJWKSet } from 'jose';
const MAX_JWKS_BYTES = 64 * 1024;
const MAX_KEYS = 20;
/** Reads a response body but gives up beyond `limit` bytes, so a hostile or broken endpoint cannot exhaust memory. */
async function readCapped(res, limit) {
    const declared = Number(res.headers.get('content-length'));
    if (Number.isFinite(declared) && declared > limit)
        throw new Error('JWKS response too large');
    if (!res.body)
        return '';
    const reader = res.body.getReader();
    const chunks = [];
    let total = 0;
    for (;;) {
        const { done, value } = await reader.read();
        if (done)
            break;
        total += value.byteLength;
        if (total > limit) {
            await reader.cancel();
            throw new Error('JWKS response too large');
        }
        chunks.push(value);
    }
    return Buffer.concat(chunks).toString('utf8');
}
/**
 * Cached JWKS with two behaviours a plain remote key set lacks:
 * - keys survive the auth service being down (stale keys are served on a failed refresh);
 * - an unknown `kid` triggers one refetch (rate limited), so key rotation is picked up at once.
 */
export function createJwksCache(options) {
    const { url, ttlMs = 3_600_000, cooldownMs = 30_000, fetch: fetchImpl = fetch, now = Date.now } = options;
    let snapshot;
    let lastAttempt = Number.NEGATIVE_INFINITY;
    let inflight;
    async function refresh() {
        lastAttempt = now();
        try {
            // No redirects: the key document must come from the auth service itself.
            const res = await fetchImpl(url, {
                headers: { accept: 'application/json' },
                redirect: 'error',
                signal: AbortSignal.timeout(5000),
            });
            if (!res.ok)
                throw new Error(`JWKS fetch failed: ${res.status}`);
            const text = await readCapped(res, MAX_JWKS_BYTES);
            const parsed = JSON.parse(text);
            if (!Array.isArray(parsed?.keys) || parsed.keys.length > MAX_KEYS)
                throw new Error('JWKS response is malformed');
            // Sessions are Ed25519 only; ignore anything else the document might contain.
            const keys = {
                keys: parsed.keys.filter((k) => k && k.kty === 'OKP' && k.crv === 'Ed25519' && typeof k.kid === 'string'),
            };
            if (keys.keys.length === 0)
                throw new Error('JWKS contains no usable keys');
            snapshot = {
                keys,
                resolve: createLocalJWKSet(keys),
                kids: new Set(keys.keys.map((k) => k.kid).filter((k) => typeof k === 'string')),
                fetchedAt: now(),
            };
        }
        catch (err) {
            // Keep serving stale keys; only fail when there is nothing at all to verify with.
            if (!snapshot)
                throw err;
        }
    }
    function refreshOnce() {
        inflight ??= refresh().finally(() => {
            inflight = undefined;
        });
        return inflight;
    }
    return async (header, token) => {
        if (!snapshot)
            await refreshOnce();
        else if (now() - snapshot.fetchedAt > ttlMs && now() - lastAttempt > cooldownMs)
            await refreshOnce();
        else if (header.kid && !snapshot.kids.has(header.kid) && now() - lastAttempt > cooldownMs)
            await refreshOnce();
        return snapshot.resolve(header, token);
    };
}
