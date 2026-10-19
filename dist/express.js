import { createAuthClient } from './core.js';
/** Express-style middleware. Sets `req.user`; answers 302 / 401 / 403 itself otherwise. */
export function authMiddleware(options) {
    const client = createAuthClient(options);
    return async function ipcharlesAuth(req, res, next) {
        try {
            if (req.method === 'OPTIONS')
                return next();
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
        }
        catch (err) {
            next(err);
        }
    };
}
