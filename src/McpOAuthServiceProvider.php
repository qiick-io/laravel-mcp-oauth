<?php

declare(strict_types=1);

namespace Qiick\McpOAuth;

use Carbon\CarbonInterval;
use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Support\ServiceProvider;
use Laravel\Passport\Passport;
use Qiick\McpOAuth\Contracts\AdminSwitch;
use Qiick\McpOAuth\Internal\BlockedHostCatalog;
use Qiick\McpOAuth\Internal\DisabledAdminSwitch;

/**
 * Registers the package in a Laravel app. Auto-discovered through
 * `extra.laravel.providers` in composer.json.
 *
 * Always calls `Passport::ignoreRoutes()` and turns the device grant off in
 * `register()` (design Resolved #3 / #4). Token TTLs come from config in
 * `boot()`. Rate limiters, default scope, bearer response type and fail-closed
 * adapter validation land with later feature PRs. While `mcp-oauth.enabled` is
 * false (the default), missing product adapters are allowed so products can
 * install before writing adapters.
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
     * Applies access and refresh TTLs from mcp-oauth config onto Passport
     * (global per app; products that already own Passport as an IdP are out of
     * scope for 1.x — design §3.3 Signaculum row).
     */
    private function configurePassportTokenLifetimes(): void
    {
        /** @var ConfigRepository $config */
        $config = $this->app->make(ConfigRepository::class);

        Passport::tokensExpireIn(CarbonInterval::minutes(
            $this->positiveIntConfig($config, 'mcp-oauth.access_token_ttl_minutes', 60),
        ));
        Passport::refreshTokensExpireIn(CarbonInterval::days(
            $this->positiveIntConfig($config, 'mcp-oauth.refresh_token_ttl_days', 30),
        ));
    }

    /**
     * Reads a positive integer from config; non-numeric values fall back.
     */
    private function positiveIntConfig(ConfigRepository $config, string $key, int $default): int
    {
        $configuredValue = $config->get($key, $default);

        if (! is_int($configuredValue) && ! is_string($configuredValue)) {
            return max(1, $default);
        }

        if (is_string($configuredValue) && ! is_numeric($configuredValue)) {
            return max(1, $default);
        }

        return max(1, (int) $configuredValue);
    }
}
