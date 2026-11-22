<?php

declare(strict_types=1);

namespace Qiick\McpOAuth;

use Illuminate\Support\Facades\Route;
use LogicException;
use Qiick\McpOAuth\Http\Controllers\RegisterClientController;
use Qiick\McpOAuth\Http\Middleware\EnsureMcpOAuthEnabledMiddleware;

/**
 * Registers the package OAuth HTTP surface the product calls from routes/mcp.php
 * (design §5.2). This slice ships DCR only; authorize / token / revoke and
 * discovery land in follow-up PRs. Throws when a foreign `passport.*` route is
 * already present (Signaculum guard, design §3.3).
 *
 * @api
 */
final class McpOAuthRoutes
{
    public static function register(): void
    {
        self::assertNoForeignPassportRoutes();

        Route::middleware([
            EnsureMcpOAuthEnabledMiddleware::class,
            'throttle:mcp-oauth-register',
        ])->post('oauth/register', RegisterClientController::class)
            ->name('mcp.oauth.register');
    }

    /**
     * Until this package registers its own `passport.*` names (token /
     * authorize / revoke), any existing `passport.*` route means a foreign
     * Passport IdP is already wired (Signaculum guard, design §3.3).
     *
     * @throws LogicException
     */
    private static function assertNoForeignPassportRoutes(): void
    {
        foreach (Route::getRoutes()->getRoutes() as $route) {
            $routeName = $route->getName();

            if (! is_string($routeName) || ! str_starts_with($routeName, 'passport.')) {
                continue;
            }

            throw new LogicException(
                "McpOAuthRoutes::register() refuses to run beside foreign Passport route [{$routeName}]. ".
                'This package is not an adopter for Signaculum-style Passport IdPs (design §3.3).',
            );
        }
    }
}
