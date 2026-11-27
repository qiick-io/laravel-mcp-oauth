<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Tests\Support;

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Process;
use Illuminate\Support\Facades\Schema;
use Orchestra\Testbench\TestCase;
use Qiick\McpOAuth\McpOAuthServiceProvider;

/**
 * Boots a Testbench Laravel app with the package provider. CI runs the suite
 * on Laravel 12 and 13, and on SQLite / PostgreSQL / MySQL / MariaDB when
 * DB_CONNECTION is set.
 */
abstract class PackageTestCase extends TestCase
{
    /**
     * No test reaches the network or spawns a process through Laravel's
     * clients unfaked (fleet convention F25). The real-HTTP and race tests
     * drive `php -S` and helper scripts with Guzzle and Symfony Process
     * directly, on purpose.
     */
    protected function setUp(): void
    {
        parent::setUp();

        Http::preventStrayRequests();
        Process::preventStrayProcesses();
    }

    /**
     * @param  Application  $app
     * @return list<class-string>
     */
    protected function getPackageProviders($app): array
    {
        return [McpOAuthServiceProvider::class];
    }

    /**
     * @param  Application  $app
     */
    protected function defineEnvironment($app): void
    {
        $app['config']->set('app.key', 'base64:'.base64_encode(random_bytes(32)));
        $app['config']->set('app.url', 'https://mcp-oauth.test');
        $app['config']->set('app.timezone', 'UTC');
        // Off by default: missing product adapters must not fail boot.
        $app['config']->set('mcp-oauth.enabled', false);

        TestDatabaseConnection::configure($app['config'], ':memory:');
    }

    protected function defineDatabaseMigrations(): void
    {
        // Persistent engines keep tables across Pest cases and runs; wipe before
        // each boot, Passport's too (the flow test cases create them again).
        foreach (['oauth_auth_codes', 'oauth_access_tokens', 'oauth_refresh_tokens', 'oauth_clients', 'oauth_device_codes'] as $passportTable) {
            Schema::dropIfExists($passportTable);
        }

        Schema::dropIfExists('oauth_consent_records');
        Schema::dropIfExists('oauth_auth_code_exchanges');
        Schema::dropIfExists('oauth_blocked_redirect_hosts');
        Schema::dropIfExists('oauth_client_metadata');
        Schema::dropIfExists('users');

        Schema::create('users', function (Blueprint $table): void {
            $table->id();
            $table->timestamp('email_verified_at')->nullable();
            $table->timestamps();
        });

        $this->loadMigrationsFrom(__DIR__.'/../../database/migrations');
    }
}
