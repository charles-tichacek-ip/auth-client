import type { FastifyPluginAsync, FastifyReply, FastifyRequest } from 'fastify';
import { createAuthClient, type AuthClientOptions, type SessionUser } from './core.js';

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

const plugin: FastifyPluginAsync<AuthPluginOptions> = async (app, options) => {
  const client = createAuthClient(options);
  app.decorateRequest('user', null);

  app.addHook('onRequest', async (request: FastifyRequest, reply: FastifyReply) => {
    // Let CORS preflights through: they never carry cookies, and @fastify/cors answers them.
    if (request.method === 'OPTIONS') return;

    const info = {
      method: request.method,
      url: request.url,
      headers: request.headers,
      fallbackBase: `${request.protocol}://${request.host}`,
    };

    if (request.routeOptions.config?.public === true) {
      request.user = await client.verifySession(request.headers.cookie);
      return;
    }

    const decision = await client.check(info);
    switch (decision.type) {
      case 'ok':
        request.user = decision.user;
        return;
      case 'public':
        request.user = decision.user;
        return;
      case 'redirect':
        return reply.redirect(decision.location);
      case 'unauthenticated':
        return reply.code(401).send({ error: 'unauthenticated' });
      case 'forbidden':
        return reply.code(403).send({ error: 'forbidden' });
      case 'bad_origin':
        return reply.code(403).send({ error: 'bad_origin' });
    }
  });
};

// Equivalent of fastify-plugin: hooks and the decorator apply to the instance it is
// registered on, not just a child scope. Register it inside an encapsulated scope to
// protect only some routes.
(plugin as unknown as Record<symbol, unknown>)[Symbol.for('skip-override')] = true;
(plugin as unknown as Record<symbol, unknown>)[Symbol.for('fastify.display-name')] = 'ipcharles-auth';

export const authPlugin = plugin;
export default plugin;
export type { SessionUser };
