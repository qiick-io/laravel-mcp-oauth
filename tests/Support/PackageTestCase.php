<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Tests\Support;

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Application;
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

        $connection = getenv('DB_CONNECTION') ?: 'sqlite';

        if ($connection === 'sqlite') {
            $app['config']->set('database.default', 'sqlite');
            $app['config']->set('database.connections.sqlite', [
                'driver' => 'sqlite',
                'database' => ':memory:',
                'prefix' => '',
                'foreign_key_constraints' => true,
            ]);

            return;
        }

        $isPgsql = $connection === 'pgsql';

        $app['config']->set('database.default', $connection);
        $app['config']->set("database.connections.{$connection}", [
            'driver' => $connection === 'mariadb' ? 'mysql' : $connection,
            'host' => getenv('DB_HOST') ?: '127.0.0.1',
            'port' => getenv('DB_PORT') ?: ($isPgsql ? '5432' : '3306'),
            'database' => getenv('DB_DATABASE') ?: 'mcp_oauth_test',
            'username' => getenv('DB_USERNAME') ?: ($isPgsql ? 'postgres' : 'root'),
            'password' => getenv('DB_PASSWORD') !== false ? (string) getenv('DB_PASSWORD') : '',
            'charset' => $isPgsql ? 'utf8' : 'utf8mb4',
            'collation' => $isPgsql ? null : 'utf8mb4_unicode_ci',
            'prefix' => '',
            'strict' => true,
            'search_path' => 'public',
        ]);
    }

    protected function defineDatabaseMigrations(): void
    {
        // Persistent engines keep tables across Pest cases; wipe before each boot.
        Schema::dropIfExists('oauth_consent_records');
        Schema::dropIfExists('oauth_blocked_redirect_hosts');
        Schema::dropIfExists('oauth_client_metadata');
        Schema::dropIfExists('users');

        Schema::create('users', function (Blueprint $table): void {
            $table->id();
            $table->timestamps();
        });

        $this->loadMigrationsFrom(__DIR__.'/../../database/migrations');
    }
}
