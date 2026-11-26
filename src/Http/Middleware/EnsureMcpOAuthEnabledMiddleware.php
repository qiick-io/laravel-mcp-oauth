<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Qiick\McpOAuth\Events\McpPassportKeysFoundMissingEvent;
use Qiick\McpOAuth\McpOAuthServer;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;

/**
 * Per-request gate for package OAuth routes (design Resolved #3 / S1–S3 / S7).
 * Off → the same 404 the router would emit for an unknown path (status, body
 * and Allow). On without usable Passport keys → 503 temporarily_unavailable
 * (an HTML page for a browser on the consent flow) and
 * {@see McpPassportKeysFoundMissingEvent}.
 */
final class EnsureMcpOAuthEnabledMiddleware
{
    public function __construct(
        private readonly McpOAuthServer $mcpOAuthServer,
    ) {}

    /**
     * @param  Closure(Request): Response  $next
     */
    public function handle(Request $request, Closure $next): Response
    {
        if (! $this->mcpOAuthServer->isEnabled()) {
            // Match Illuminate\Routing\AbstractRouteCollection::handleMatchedRoute
            // so scanners cannot tell a gated route from a missing one.
            throw new NotFoundHttpException(sprintf(
                'The route %s could not be found.',
                $request->path(),
            ));
        }

        if (! $this->mcpOAuthServer->hasPassportKeys()) {
            event(new McpPassportKeysFoundMissingEvent(
                endpoint: $request->path(),
                reason: 'unreadable',
            ));

            // A browser on the consent flow gets a page, not JSON (design §4.2).
            if ($request->routeIs('passport.authorizations.*') && ! $request->expectsJson()) {
                // This group runs before the route's framing middleware, so the page sets its own.
                return response(
                    '<!doctype html><title>Sign-in unavailable</title><p>Connecting apps is temporarily unavailable. Try again later.</p>',
                    503,
                    ['X-Frame-Options' => 'DENY', 'Content-Security-Policy' => "frame-ancestors 'none'"],
                );
            }

            return response()->json([
                'error' => 'temporarily_unavailable',
                'error_description' => 'OAuth is unavailable because Passport keys are missing.',
            ], 503);
        }

        return $next($request);
    }
}
