import type { FastifyPluginAsync } from 'fastify';
import { type AuthClientOptions, type SessionUser } from './core.js';
declare module 'fastify' {
    interface FastifyRequest {
        /** The signed-in, allowed user. Null only on public routes without a valid session. */
        user: SessionUser | null;
    }
    interface FastifyContextConfig {
        /** Set `config: { public: true }` on a route to serve it without authentication. */
        public?: boolean;
    }
}
export type AuthPluginOptions = AuthClientOptions;
declare const plugin: FastifyPluginAsync<AuthPluginOptions>;
export declare const authPlugin: FastifyPluginAsync<AuthClientOptions>;
export default plugin;
export type { SessionUser };
