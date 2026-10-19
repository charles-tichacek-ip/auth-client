import type { IncomingHttpHeaders } from 'node:http';
import { createAuthClient, type AuthClientOptions, type SessionUser } from './core.js';

// Structural types so this works with Express 4 and 5 without depending on either.
interface ReqLike {
  method: string;
  originalUrl?: string;
  url: string;
  headers: IncomingHttpHeaders;
  protocol: string;
  get(name: string): string | undefined;
  user?: SessionUser | null;
}
interface ResLike {
  status(code: number): ResLike;
  json(body: unknown): unknown;
  redirect(url: string): unknown;
}
type Next = (err?: unknown) => void;

export type AuthMiddlewareOptions = AuthClientOptions;

/** Express-style middleware. Sets `req.user`; answers 302 / 401 / 403 itself otherwise. */
export function authMiddleware(options: AuthMiddlewareOptions) {
  const client = createAuthClient(options);
  return async function ipcharlesAuth(req: ReqLike, res: ResLike, next: Next): Promise<void> {
    try {
      if (req.method === 'OPTIONS') return next();
      const decision = await client.check({
        method: req.method,
        url: req.originalUrl ?? req.url,
        headers: req.headers,
        fallbackBase: `${req.protocol}://${req.get('host') ?? 'localhost'}`,
      });
      switch (decision.type) {
        case 'ok':
        case 'public':
          req.user = decision.user;
          return next();
        case 'redirect':
          res.redirect(decision.location);
          return;
        case 'unauthenticated':
          res.status(401).json({ error: 'unauthenticated' });
          return;
        case 'forbidden':
          res.status(403).json({ error: 'forbidden' });
          return;
        case 'bad_origin':
          res.status(403).json({ error: 'bad_origin' });
          return;
      }
    } catch (err) {
      next(err);
    }
  };
}

export type { SessionUser };
