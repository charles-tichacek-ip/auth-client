import type { IncomingHttpHeaders } from 'node:http';
import { type AuthClientOptions, type SessionUser } from './core.js';
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
export declare function authMiddleware(options: AuthMiddlewareOptions): (req: ReqLike, res: ResLike, next: Next) => Promise<void>;
export type { SessionUser };
