
class CustomRouter {
    constructor() {
        this.routes = [];
    }

    add(method, path, handler) {
        // Convert ITTY-router style path params (e.g., /api/labs/:id) to regex
        const regexPath = new RegExp(
            '^' + path.replace(/:(\w+)/g, '(?<$1>[^/]+)').replace(/\*/g, '.*?') + '$'
        );
        this.routes.push({ method, regexPath, handler });
    }

    get(path, handler) { this.add('GET', path, handler); }
    post(path, handler) { this.add('POST', path, handler); }
    put(path, handler) { this.add('PUT', path, handler); }
    delete(path, handler) { this.add('DELETE', path, handler); }
    all(path, handler) { this.add('ALL', path, handler); }

    async handle(request, env, ctx) {
        console.log('--- CustomRouter.handle start ---');
        const { pathname } = new URL(request.url);
        console.log('Request Method:', request.method, 'Pathname:', pathname);

        for (const route of this.routes) {
            console.log('Checking route:', route.method, route.regexPath.source);
            if ((route.method === request.method || route.method === 'ALL') && route.regexPath.test(pathname)) {
                console.log('Route matched:', route.method, route.regexPath.source);
                const match = pathname.match(route.regexPath);
                const params = match ? match.groups || {} : {};
                
                // Attach params to request object. Use spread to allow multiple ALL handlers to add params.
                request.params = { ...request.params, ...params }; 
                console.log('Route params:', request.params);

                try {
                    // Call the handler
                    let currentResponse = await route.handler(request, env, ctx);
                    console.log('Route handler currentResponse:', currentResponse);

                    // If the handler returned a Response, return it.
                    // If it's an ALL handler that returned undefined, it acts as middleware, so continue.
                    if (currentResponse instanceof Response) {
                        console.log('Returning currentResponse as it is a Response object.');
                        return currentResponse;
                    }
                    // If an ALL handler returns undefined, it's treated as middleware, so continue to the next route.
                    // For specific methods, a non-Response return here would imply an error or unexpected behavior,
                    // but the logic below will catch if no *other* specific route returns a Response.
                    // This block ensures only Response objects are explicitly returned.
                    if (route.method === request.method) {
                        // If a specific method handler returns non-Response, it's an error.
                        // This should ideally be caught by the outer fetch, but better to be explicit.
                        console.error('Specific method handler did not return a Response. Route:', route.regexPath.source);
                        return new Response('Internal Server Error: Specific route handler did not return a Response.', { status: 500 });
                    }

                } catch (e) {
                    console.error('Route handler error:', e);
                    return new Response('Internal Server Error', { status: 500 });
                }
            }
        }
        
        console.log('No route matched, returning 404.');
        // If no route matches, return a 404.
        return new Response('Not Found.', { status: 404 });
    }
}

export { CustomRouter as Router };
