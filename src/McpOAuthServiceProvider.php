<?php

declare(strict_types=1);

namespace Qiick\McpOAuth;

use Carbon\CarbonInterval;
use Illuminate\Cache\RateLimiting\Limit;
use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Support\ServiceProvider;
use Laravel\Passport\Passport;
use League\OAuth2\Server\AuthorizationServer;
use League\OAuth2\Server\Grant\AuthCodeGrant;
use League\OAuth2\Server\Grant\ClientCredentialsGrant;
use Qiick\McpOAuth\Contracts\AdminSwitch;
use Qiick\McpOAuth\Internal\BlockedHostCatalog;
use Qiick\McpOAuth\Internal\BoundedPositiveInt;
use Qiick\McpOAuth\Internal\DisabledAdminSwitch;
use ReflectionProperty;

/**
 * Registers the package in a Laravel app. Auto-discovered through
 * `extra.laravel.providers` in composer.json.
 *
 * Always calls `Passport::ignoreRoutes()` and turns the device grant off in
 * `register()` (design Resolved #3 / #4). Token TTLs, the wire scope
 * (`tokensCan` / `defaultScopes`), stripping ClientCredentialsGrant,
 * `McpBearerTokenResponse`, and the `mcp-oauth-register` /
 * `mcp-oauth-token` rate limiters (keyed by ClientThrottleKey) land in
 * `boot()`. Fail-closed adapter validation lands with later feature PRs.
 * While `mcp-oauth.enabled` is false (the default), missing product
 * adapters are allowed so products can install before writing adapters.
 *
 * @api
 */
final class McpOAuthServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../config/mcp-oauth.php', 'mcp-oauth');

        // Always: Passport must not register its own /oauth/* (S4).
        Passport::ignoreRoutes();
        Passport::$deviceCodeGrantEnabled = false;

        $this->app->singletonIf(AdminSwitch::class, DisabledAdminSwitch::class);

        $this->app->singleton(BlockedHostCatalog::class, static fn (): BlockedHostCatalog => new BlockedHostCatalog);

        $this->app->singleton(RedirectUriGuard::class, function (Application $app): RedirectUriGuard {
            return new RedirectUriGuard($app->make(BlockedHostCatalog::class));
        });

        $this->app->singleton(McpOAuthServer::class, function (Application $app): McpOAuthServer {
            return new McpOAuthServer(
                $app->make(ConfigRepository::class),
                $app->make(AdminSwitch::class),
            );
        });

        $this->app->singleton(McpOAuthReadiness::class, function (Application $app): McpOAuthReadiness {
            return new McpOAuthReadiness($app->make(McpOAuthServer::class));
        });
    }

    public function boot(): void
    {
        // Core side tables load with the package (same pattern as laravel-oidc).
        // Opt out via mcp-oauth.migrations.load when the app owns the files.
        if ($this->app->make('config')->get('mcp-oauth.migrations.load', true)) {
            $this->loadMigrationsFrom(__DIR__.'/../database/migrations');
        }

        $this->configurePassportTokenLifetimes();
        $this->configurePassportScopes();
        Passport::useAuthorizationServerResponseType(new McpBearerTokenResponse);
        $this->configureRateLimiters();

        if ($this->app->runningInConsole()) {
            $this->publishes([
                __DIR__.'/../config/mcp-oauth.php' => config_path('mcp-oauth.php'),
            ], 'mcp-oauth-config');

            $this->publishesMigrations([
                __DIR__.'/../database/migrations' => database_path('migrations'),
            ], 'mcp-oauth-migrations');
        }
    }

    /**
     * Applies access, refresh and auth-code TTLs from mcp-oauth config onto
     * Passport (global per app; products that already own Passport as an IdP
     * are out of scope for 1.x — design §3.3 Signaculum row). Invalid values
     * fail closed at boot (design §6); they are never floored or replaced.
     */
    private function configurePassportTokenLifetimes(): void
    {
        /** @var ConfigRepository $config */
        $config = $this->app->make(ConfigRepository::class);

        $accessTokenTtlMinutes = BoundedPositiveInt::require(
            $config->get('mcp-oauth.access_token_ttl_minutes'),
            'access_token_ttl_minutes',
            BoundedPositiveInt::ACCESS_TOKEN_TTL_MINUTES_MAX,
        );
        $refreshTokenTtlDays = BoundedPositiveInt::require(
            $config->get('mcp-oauth.refresh_token_ttl_days'),
            'refresh_token_ttl_days',
            BoundedPositiveInt::REFRESH_TOKEN_TTL_DAYS_MAX,
        );
        $authCodeTtlMinutes = BoundedPositiveInt::require(
            $config->get('mcp-oauth.auth_code_ttl_minutes'),
            'auth_code_ttl_minutes',
            BoundedPositiveInt::AUTH_CODE_TTL_MINUTES_MAX,
        );

        Passport::tokensExpireIn(CarbonInterval::minutes($accessTokenTtlMinutes));
        Passport::refreshTokensExpireIn(CarbonInterval::days($refreshTokenTtlDays));
        $this->hardenAuthorizationServer($authCodeTtlMinutes);
    }

    /**
     * Passport hardcodes AuthCodeGrant at PT10M and always enables
     * ClientCredentialsGrant. Patch the live AuthorizationServer: set the
     * validated auth-code TTL, and drop client_credentials so Passport’s
     * hard-coded `*` scope cannot be issued for MCP (design: auth code +
     * refresh only). Retrofits an already-resolved singleton.
     */
    private function hardenAuthorizationServer(int $authCodeTtlMinutes): void
    {
        $authCodeInterval = CarbonInterval::minutes($authCodeTtlMinutes);

        $harden = function (AuthorizationServer $authorizationServer) use ($authCodeInterval): void {
            $enabledGrantTypesProperty = new ReflectionProperty($authorizationServer, 'enabledGrantTypes');
            /** @var array<string, object> $enabledGrantTypes */
            $enabledGrantTypes = $enabledGrantTypesProperty->getValue($authorizationServer);

            foreach ($enabledGrantTypes as $grantIdentifier => $grant) {
                if ($grant instanceof ClientCredentialsGrant) {
                    unset($enabledGrantTypes[$grantIdentifier]);

                    continue;
                }

                if (! $grant instanceof AuthCodeGrant) {
                    continue;
                }

                $authCodeTtlProperty = new ReflectionProperty(AuthCodeGrant::class, 'authCodeTTL');
                $authCodeTtlProperty->setValue($grant, $authCodeInterval);
            }

            $enabledGrantTypesProperty->setValue($authorizationServer, $enabledGrantTypes);
        };

        $this->app->afterResolving(AuthorizationServer::class, $harden);

        if ($this->app->resolved(AuthorizationServer::class)) {
            $harden($this->app->make(AuthorizationServer::class));
        }
    }

    /**
     * Registers the wire scope descriptions and default scope (design §5.6).
     */
    private function configurePassportScopes(): void
    {
        /** @var McpOAuthServer $server */
        $server = $this->app->make(McpOAuthServer::class);

        Passport::tokensCan($server->scopeDescriptions());
        Passport::defaultScopes([McpOAuthServer::WIRE_SCOPE]);
    }

    /**
     * Named limiters for DCR and the token endpoint (design §5.6). Routes
     * attach `throttle:mcp-oauth-register` / `throttle:mcp-oauth-token` when
     * those endpoints land; both keys use ClientThrottleKey (S29 / S30).
     */
    private function configureRateLimiters(): void
    {
        /** @var ConfigRepository $config */
        $config = $this->app->make(ConfigRepository::class);

        $registrationsPerMinute = BoundedPositiveInt::require(
            $config->get('mcp-oauth.registrations_per_minute'),
            'registrations_per_minute',
            BoundedPositiveInt::RATE_LIMIT_PER_MINUTE_MAX,
        );
        $tokenRequestsPerMinute = BoundedPositiveInt::require(
            $config->get('mcp-oauth.token_requests_per_minute'),
            'token_requests_per_minute',
            BoundedPositiveInt::RATE_LIMIT_PER_MINUTE_MAX,
        );

        RateLimiter::for('mcp-oauth-register', static function (Request $request) use ($registrationsPerMinute): Limit {
            return Limit::perMinute($registrationsPerMinute)->by(ClientThrottleKey::fromRequest($request));
        });

        RateLimiter::for('mcp-oauth-token', static function (Request $request) use ($tokenRequestsPerMinute): Limit {
            return Limit::perMinute($tokenRequestsPerMinute)->by(ClientThrottleKey::fromRequest($request));
        });
    }
}
