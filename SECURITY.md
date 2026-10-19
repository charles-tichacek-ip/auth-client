# Security policy

This package decides who is signed in to personal apps, so reports are taken seriously.

**Report a vulnerability** privately through GitHub: *Security* tab, *Report a vulnerability*. Please do not open a public issue for anything that could let someone bypass sign-in, the allowlist, or the `Origin` check.

## Design properties worth checking

- Tokens are accepted only if signed with EdDSA by a key from the auth service's JWKS, with the expected issuer, an expiry, a `kid`, a string `sub` and a string `name`. Header-supplied keys (`jwk`, `jku`, `x5u`, `x5c`) are refused.
- The auth URL must be https (plain http only for localhost) and must not carry credentials; the JWKS fetch refuses redirects, caps the response at 64 KiB and ignores non-Ed25519 keys.
- `allow` is required and must return exactly `true`. If it throws, the request is not admitted.
- `baseUrl` is required outside localhost, so the `Origin` check and the sign-in `return` address never depend on the `Host` header.
- State-changing requests need an allowed `Origin`; a missing `Origin` is refused unless explicitly permitted.
- The only runtime dependency is `jose`. CI fails if the committed `dist/` differs from a clean build of the source.

## Supply chain notes for apps that install this

- Install from a commit you have reviewed. `package-lock.json` records the exact commit a `#vX.Y.Z` tag resolved to; keep the lockfile committed and use `npm ci`.
- Tags and `main` are protected against force-push and deletion on this repository, but a lockfile is still the stronger pin.
