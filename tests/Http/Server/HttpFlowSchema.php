<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Tests\Http\Server;

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * Builds, from scratch, the tables the served app uses: the users table,
 * Passport's tables with the product's binding columns (as the
 * mcp-oauth-binding-stub-uuid stub adds them), the package's own tables
 * (loaded from its migrations) and the product grant table.
 */
final class HttpFlowSchema
{
    public static function create(): void
    {
        $passportTables = ['oauth_auth_codes', 'oauth_access_tokens', 'oauth_refresh_tokens', 'oauth_clients', 'oauth_device_codes'];
        $packageTables = ['oauth_consent_records', 'oauth_auth_code_exchanges', 'oauth_blocked_redirect_hosts', 'oauth_client_metadata'];

        foreach ([...$passportTables, ...$packageTables, DatabaseGrantStore::TABLE, 'users', 'migrations'] as $table) {
            Schema::dropIfExists($table);
        }

        Schema::create('users', static function (Blueprint $table): void {
            $table->id();
            $table->timestamp('email_verified_at')->nullable();
            $table->timestamps();
        });

        $passportMigrations = glob(__DIR__.'/../../../vendor/laravel/passport/database/migrations/*.php') ?: [];
        $packageMigrations = glob(__DIR__.'/../../../database/migrations/*.php') ?: [];

        foreach ([...$passportMigrations, ...$packageMigrations] as $migrationFile) {
            (require $migrationFile)->up();
        }

        Schema::table('oauth_access_tokens', static function (Blueprint $table): void {
            $table->uuid('api_key_id')->nullable()->index();
            $table->string('audience', 512)->nullable();
        });

        Schema::create(DatabaseGrantStore::TABLE, static function (Blueprint $table): void {
            $table->uuid('id')->primary();
            $table->uuid('client_id')->index();
            $table->string('user_identifier');
            $table->boolean('revoked')->default(false);
            $table->string('revocation_reason', 32)->nullable();
            $table->json('scopes');
            $table->json('resource_scopes');
            $table->uuid('organisation_id')->nullable();
            $table->uuid('install_id')->nullable();
            $table->char('companion_jkt', 43)->nullable();
            $table->index(['client_id', 'user_identifier', 'organisation_id', 'install_id'], 'http_flow_grants_install_idx');
            $table->timestamp('authorized_at');
            $table->timestamp('revoked_at')->nullable();
        });
    }
}
