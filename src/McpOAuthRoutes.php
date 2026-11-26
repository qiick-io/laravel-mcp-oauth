<?php

declare(strict_types=1);

namespace Qiick\McpOAuth;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Str;
use Laravel\Mcp\Server\Http\Controllers\OAuthRegisterController;
use Laravel\Mcp\Server\Middleware\AddAuthorizationFramingHeaders;
use LogicException;
use Qiick\McpOAuth\Http\Controllers\ApproveClientController;
use Qiick\McpOAuth\Http\Controllers\AuthorizationServerMetadataController;
use Qiick\McpOAuth\Http\Controllers\AuthorizeClientController;
use Qiick\McpOAuth\Http\Controllers\DenyClientController;
use Qiick\McpOAuth\Http\Controllers\IssueTokenController;
use Qiick\McpOAuth\Http\Controllers\ProtectedResourceMetadataController;
use Qiick\McpOAuth\Http\Controllers\RegisterClientController;
use Qiick\McpOAuth\Http\Controllers\RevokeTokenController;
use Qiick\McpOAuth\Http\Middleware\EnsureMcpOAuthEnabledMiddleware;
use Qiick\McpOAuth\Http\Middleware\ValidateAuthorizationRequestMiddleware;
use Qiick\McpOAuth\Http\Middleware\ValidateTokenRequestMiddleware;
use Symfony\Component\HttpKernel\Exception\HttpException;
use Symfony\Component\HttpKernel\Exception\MethodNotAllowedHttpException;

/**
 * Registers the package OAuth HTTP surface the product calls from routes/mcp.php
 * (design §5.2): DCR, the token, revocation and authorization endpoints with
 * consent, and the RFC 8414 / RFC 9728 discovery documents. It replaces
 * `Mcp::oauthRoutes()`; the product does not call that. Throws when a foreign `passport.*` route is
 * already present (Signaculum guard, design §3.3).
 *
 * Every route, every HTTP method of `oauth/*` included, sits behind
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
            // The router adds HEAD to every GET route.
            Route::match(
                ['GET', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
                'oauth/register',
                static function (): never {
                    throw new MethodNotAllowedHttpException(['POST']);
                },
            );

            Route::post('oauth/register', RegisterClientController::class)
                ->middleware('throttle:mcp-oauth-register')
                ->name('mcp.oauth.register');

            self::registerTokenRoutes();

            if (app(McpOAuthServer::class)->revocationEndpointUrl() !== null) {
                self::registerRevocationRoutes();
            }

            self::registerAuthorizationRoutes();
            self::registerDiscoveryRoutes();
        });

        // ->name() is applied after addRoute; rebuild so Route::has() sees it.
        Route::getRoutes()->refreshNameLookups();
    }

    /**
     * Token endpoint (design §5.2 item 6). Stateless: no `web` group, so no
     * session and no CSRF, as RFC 6749 §3.2 expects of a client-facing API.
     * The throttle runs before the request checks, so refusals count too.
     */
    private static function registerTokenRoutes(): void
    {
        Route::match(['GET', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'], 'oauth/token', static function (): never {
            throw new MethodNotAllowedHttpException(['POST']);
        });

        Route::post('oauth/token', [IssueTokenController::class, 'issueToken'])
            ->middleware(['throttle:mcp-oauth-token', ValidateTokenRequestMiddleware::class])
            ->name('passport.token');
    }

    /**
     * RFC 7009 revocation (standards review S1). Stateless like the token
     * endpoint, with its own `mcp-oauth-revoke` limiter.
     */
    private static function registerRevocationRoutes(): void
    {
        Route::match(['GET', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'], 'oauth/revoke', static function (): never {
            throw new MethodNotAllowedHttpException(['POST']);
        });

        Route::post('oauth/revoke', RevokeTokenController::class)
            ->middleware('throttle:mcp-oauth-revoke')
            ->name('mcp.oauth.revoke');
    }

    /**
     * RFC 8414 and RFC 9728 documents (design §5.2 items 2–4). They replace
     * `Mcp::oauthRoutes()`, which a product must not call: its documents are
     * built from the request Host and sit outside the off-gate. Both documents
     * are served at the root and at the MCP path only; any other nested path
     * is a 404, so no other resource or issuer is advertised.
     */
    private static function registerDiscoveryRoutes(): void
    {
        $mcpOAuthServer = app(McpOAuthServer::class);
        $mcpPath = Str::after($mcpOAuthServer->resourceIdentifier(), $mcpOAuthServer->issuer().'/');

        Route::get('.well-known/oauth-authorization-server', AuthorizationServerMetadataController::class)
            ->name('mcp.oauth.authorization-server');

        // Some MCP clients look for it under the resource path; any other path
        // would name an issuer that is not this one (RFC 8414 §3.3).
        Route::get('.well-known/oauth-authorization-server/'.$mcpPath, AuthorizationServerMetadataController::class)
            ->name('mcp.oauth.authorization-server.mcp');

        Route::get('.well-known/oauth-protected-resource', ProtectedResourceMetadataController::class)
            ->name('mcp.oauth.protected-resource');

        // Not named `mcp.oauth.protected-resource.nested`: laravel/mcp's
        // AddWwwAuthenticateHeader adds a `resource_metadata` pointer to the
        // /mcp 401 as soon as a route has that name, built from the request
        // host and shown even while OAuth is off (when it would lead to a 404).
        // The package's own challenge comes with the /mcp door; until then
        // clients find these documents at the well-known paths.
        Route::get('.well-known/oauth-protected-resource/'.$mcpPath, ProtectedResourceMetadataController::class)
            ->name('mcp.oauth.protected-resource.mcp');
    }

    /**
     * Authorization endpoint and consent (design §5.2 item 7). Inside the
     * off-gate, so `web` (session, CSRF) and the framing headers only run once
     * OAuth is on: off, the path answers exactly like a missing route.
     * AddAuthorizationFramingHeaders sets `X-Frame-Options: DENY` and
     * `frame-ancestors 'none'` on the `passport.authorizations.*` names,
     * error responses included.
     */
    private static function registerAuthorizationRoutes(): void
    {
        // Framing outside `web`, so a CSRF 419 thrown inside `web` carries it too.
        Route::middleware([AddAuthorizationFramingHeaders::class, 'web', 'throttle:mcp-oauth-authorize'])
            ->group(static function (): void {
                // Named under passport.authorizations.* so the framing middleware covers it.
                Route::match(['PUT', 'PATCH', 'OPTIONS'], 'oauth/authorize', static function (): never {
                    throw new MethodNotAllowedHttpException(['GET', 'HEAD', 'POST', 'DELETE']);
                })->name('passport.authorizations.unsupported-method');

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
     * What stops the package from serving the endpoints its metadata
     * advertises (design §4.3), for switch-on and `mcp-oauth:check`. Each
     * advertised URL (authorize, approve, deny, token, register, revoke when
     * it is advertised, both metadata documents) is matched against the live
     * route collection as a request to the issuer would be, host included,
     * and the route it selects must be the package's controller. A route
     * name proves nothing: a prefixed mount, a mount for another domain or a
     * foreign handler under the same URL would pass it. Also lists foreign
     * `passport.*` routes and laravel/mcp's own OAuth routes.
     *
     * @return list<string>
     */
    public static function servingProblems(): array
    {
        $mcpOAuthServer = app(McpOAuthServer::class);
        $issuer = $mcpOAuthServer->issuer();
        $metadata = $mcpOAuthServer->authorizationServerMetadata();
        /** @var string $authorizationEndpoint */
        $authorizationEndpoint = $metadata['authorization_endpoint'];
        /** @var string $tokenEndpoint */
        $tokenEndpoint = $metadata['token_endpoint'];
        /** @var string $registrationEndpoint */
        $registrationEndpoint = $metadata['registration_endpoint'];

        $advertisedEndpoints = [
            ['GET', $authorizationEndpoint, AuthorizeClientController::class],
            ['POST', $authorizationEndpoint, ApproveClientController::class],
            ['DELETE', $authorizationEndpoint, DenyClientController::class],
            ['POST', $tokenEndpoint, IssueTokenController::class],
            ['POST', $registrationEndpoint, RegisterClientController::class],
            ['GET', $issuer.'/.well-known/oauth-authorization-server', AuthorizationServerMetadataController::class],
            ['GET', $issuer.'/.well-known/oauth-protected-resource', ProtectedResourceMetadataController::class],
        ];
        $revocationEndpoint = $mcpOAuthServer->revocationEndpointUrl();

        if ($revocationEndpoint !== null) {
            $advertisedEndpoints[] = ['POST', $revocationEndpoint, RevokeTokenController::class];
        }

        $problems = [];

        foreach ($advertisedEndpoints as [$method, $url, $controllerClass]) {
            try {
                $selectedRoute = Route::getRoutes()->match(Request::create($url, $method));
            } catch (HttpException) {
                $problems[] = "{$method} {$url} is not served";

                continue;
            }

            if ($selectedRoute->getControllerClass() !== $controllerClass) {
                $problems[] = "{$method} {$url} is served by another handler";
            }
        }

        foreach (self::foreignPassportRouteNames() as $routeName) {
            $problems[] = "foreign Passport route {$routeName}";
        }

        foreach (self::laravelMcpOAuthRouteNames() as $routeName) {
            $problems[] = "laravel/mcp OAuth route {$routeName}";
        }

        return $problems;
    }

    /**
     * laravel/mcp's own OAuth routes (`Mcp::oauthRoutes()`): its nested
     * discovery documents build every endpoint and the resource from the
     * request Host, and its registration has none of the package's guards.
     * The package's routes replace them (design §5.2, S13), so beside OAuth
     * they must not be mounted. The root documents share the package's names
     * and are skipped by laravel/mcp once the package registered them.
     *
     * @return list<string>
     */
    public static function laravelMcpOAuthRouteNames(): array
    {
        $laravelMcpRouteNames = [];

        foreach (Route::getRoutes()->getRoutes() as $route) {
            $routeName = (string) $route->getName();
            $isNestedDocument = in_array($routeName, ['mcp.oauth.protected-resource.nested', 'mcp.oauth.authorization-server.nested'], true);

            if ($isNestedDocument || $route->getControllerClass() === OAuthRegisterController::class) {
                $laravelMcpRouteNames[] = $routeName;
            }
        }

        return $laravelMcpRouteNames;
    }

    /**
     * `passport.*` routes registered by someone else, such as a Passport IdP
     * (design §3.3), for `mcp-oauth:check`.
     *
     * @return list<string>
     */
    public static function foreignPassportRouteNames(): array
    {
        // The `passport.*` routes this package registers. A local list, not a
        // class constant: pcov never covers a constant, so mutation could not
        // test the names.
        $packageRouteNames = [
            'passport.token',
            'passport.authorizations.authorize',
            'passport.authorizations.approve',
            'passport.authorizations.deny',
            'passport.authorizations.unsupported-method',
        ];
        $foreignRouteNames = [];

        foreach (Route::getRoutes()->getRoutes() as $route) {
            $routeName = $route->getName();

            if (is_string($routeName) && str_starts_with($routeName, 'passport.') && ! in_array($routeName, $packageRouteNames, true)) {
                $foreignRouteNames[] = $routeName;
            }
        }

        return $foreignRouteNames;
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
