<?php

declare(strict_types=1);

namespace Qiick\McpOAuth;

use Illuminate\Support\ServiceProvider;

/**
 * Registers the package in a Laravel app. Auto-discovered through
 * `extra.laravel.providers` in composer.json.
 *
 * Passport ignoreRoutes, device-grant off, contract bindings, rate limiters and
 * fail-closed boot validation land with the feature PRs that need them. While
 * `mcp-oauth.enabled` is false (the default), missing product adapters are
 * allowed so products can install before writing adapters.
 *
 * @api
 */
final class McpOAuthServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../config/mcp-oauth.php', 'mcp-oauth');
    }

    public function boot(): void
    {
        if ($this->app->runningInConsole()) {
            $this->publishes([
                __DIR__.'/../config/mcp-oauth.php' => config_path('mcp-oauth.php'),
            ], 'mcp-oauth-config');
        }
    }
}
