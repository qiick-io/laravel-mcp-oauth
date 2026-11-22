<?php

declare(strict_types=1);

namespace Qiick\McpOAuth;

use Illuminate\Support\Facades\Route;
use Laravel\Mcp\Server\Middleware\AddAuthorizationFramingHeaders;
use LogicException;
use Qiick\McpOAuth\Http\Controllers\ApproveClientController;
use Qiick\McpOAuth\Http\Controllers\AuthorizeClientController;
use Qiick\McpOAuth\Http\Controllers\DenyClientController;
use Qiick\McpOAuth\Http\Controllers\RegisterClientController;
use Qiick\McpOAuth\Http\Middleware\EnsureMcpOAuthEnabledMiddleware;
use Qiick\McpOAuth\Http\Middleware\ValidateAuthorizationRequestMiddleware;
use Symfony\Component\HttpKernel\Exception\MethodNotAllowedHttpException;

/**
 * Registers the package OAuth HTTP surface the product calls from routes/mcp.php
 * (design §5.2): DCR and the authorization endpoint with consent; token,
 * revoke and discovery land in follow-up PRs. Throws when a foreign `passport.*` route is
 * already present (Signaculum guard, design §3.3).
 *
 * Every HTTP method for `oauth/register` sits behind
 * {@see EnsureMcpOAuthEnabledMiddleware} so that, with OAuth off, the path is
 * indistinguishable from a route that was never registered (design §4.2).
 *
 * @api
 */
final class McpOAuthRoutes
{
    public static function register(): void
    {
        self::assertNoForeignPassportRoutes();

        Route::middleware([EnsureMcpOAuthEnabledMiddleware::class])->group(static function (): void {
            // Non-POST methods share the off-gate. When OAuth is on they 405;
            // when off the middleware already answered the router's 404.
            Route::match(
                ['GET', 'HEAD', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'], // @pest-mutate-ignore: RemoveArrayItem — every non-POST verb must share the off-gate
                'oauth/register',
                static function (): never {
                    throw new MethodNotAllowedHttpException(['POST']); // @pest-mutate-ignore: RemoveArrayItem — Allow: POST when OAuth is on
                },
            );

            Route::post('oauth/register', RegisterClientController::class)
                ->middleware('throttle:mcp-oauth-register')
                ->name('mcp.oauth.register');

            self::registerAuthorizationRoutes();
        });

        // ->name() is applied after addRoute; rebuild so Route::has() sees it.
        Route::getRoutes()->refreshNameLookups();
    }

    /**
     * Authorization endpoint and consent (design §5.2 item 7). Inside the
     * off-gate, so `web` (session, CSRF) and the framing headers only run once
     * OAuth is on: off, the path answers exactly like a missing route.
     * AddAuthorizationFramingHeaders sets `X-Frame-Options: DENY` and
     * `frame-ancestors 'none'` on the `passport.authorizations.*` names.
     */
    private static function registerAuthorizationRoutes(): void
    {
        Route::middleware(['web', AddAuthorizationFramingHeaders::class, 'throttle:mcp-oauth-authorize'])
            ->group(static function (): void {
                Route::match(['PUT', 'PATCH', 'OPTIONS'], 'oauth/authorize', static function (): never {
                    throw new MethodNotAllowedHttpException(['GET', 'HEAD', 'POST', 'DELETE']);
                });

                Route::get('oauth/authorize', [AuthorizeClientController::class, 'authorize'])
                    ->middleware(ValidateAuthorizationRequestMiddleware::class)
                    ->name('passport.authorizations.authorize');

                Route::middleware(['auth', 'verified'])->group(static function (): void {
                    Route::post('oauth/authorize', ApproveClientController::class)
                        ->name('passport.authorizations.approve');

                    Route::delete('oauth/authorize', DenyClientController::class)
                        ->name('passport.authorizations.deny');
                });
            });
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
                continue; // @pest-mutate-ignore: ContinueToBreak — must keep scanning for a later passport.* name
            }

            // Message shape is fixed copy; order of the two clauses is not load-bearing.
            throw new LogicException( // @pest-mutate-ignore: ConcatSwitchSides
                "McpOAuthRoutes::register() refuses to run beside foreign Passport route [{$routeName}]. ".
                'This package is not an adopter for Signaculum-style Passport IdPs (design §3.3).',
            );
        }
    }
}
