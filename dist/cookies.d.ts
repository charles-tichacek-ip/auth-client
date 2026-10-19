/**
 * Values for `name` in a Cookie header, in order, at most five. Duplicates happen when a
 * host-only and a domain cookie coexist; the cap stops a crafted header from forcing many verifications.
 */
export declare function cookieValues(header: string | undefined, name: string): string[];
