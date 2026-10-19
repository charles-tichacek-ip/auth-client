const MAX_VALUES = 5;

/**
 * Values for `name` in a Cookie header, in order, at most five. Duplicates happen when a
 * host-only and a domain cookie coexist; the cap stops a crafted header from forcing many verifications.
 */
export function cookieValues(header: string | undefined, name: string): string[] {
  if (!header) return [];
  const values: string[] = [];
  for (const part of header.split(';')) {
    const eq = part.indexOf('=');
    if (eq === -1) continue;
    if (part.slice(0, eq).trim() !== name) continue;
    let value = part.slice(eq + 1).trim();
    if (value.startsWith('"') && value.endsWith('"') && value.length >= 2) value = value.slice(1, -1);
    values.push(value);
    if (values.length >= MAX_VALUES) break;
  }
  return values;
}
