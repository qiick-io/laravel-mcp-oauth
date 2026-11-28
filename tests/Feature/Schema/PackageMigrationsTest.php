<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Str;
use LogicException;
use Qiick\McpOAuth\Models\OAuthAuthCodeExchange;
use Qiick\McpOAuth\Models\OAuthBlockedRedirectHost;
use Qiick\McpOAuth\Models\OAuthClientMetadata;
use Qiick\McpOAuth\Models\OAuthConsentRecord;

/**
 * Red-first schema gates for standards review MUST/SHOULD table items.
 * Each test name cites the checklist id it proves.
 */

/**
 * @param  list<string>  $columns
 */
function tableHasUniqueIndexCovering(string $table, array $columns): bool
{
    foreach (Schema::getIndexes($table) as $index) {
        if (! ($index['unique'] ?? false)) {
            continue;
        }

        if (array_values($index['columns'] ?? []) === array_values($columns)) {
            return true;
        }
    }

    return false;
}

it('M3: oauth_client_metadata has every RFC 7591, CIMD, PAR/DPoP and retention column', function (): void {
    $requiredColumns = [
        'id', 'client_id', 'registration_source', 'spec_revision', 'application_type',
        'client_uri', 'logo_uri', 'tos_uri', 'policy_uri', 'contacts',
        'software_id', 'software_version', 'software_statement',
        'token_endpoint_auth_method', 'jwks_uri', 'jwks',
        'client_id_issued_at', 'first_authorized_at', 'client_secret_expires_at',
        'registration_access_token_hash', 'registration_access_token_expires_at',
        'metadata_document_url', 'metadata_document_url_sha256', 'metadata_document',
        'metadata_document_sha256', 'metadata_document_etag',
        'metadata_document_fetched_at', 'metadata_document_expires_at',
        'metadata_document_status', 'metadata_document_error',
        'require_pushed_authorization_requests', 'dpop_bound_access_tokens',
        'revoked_at', 'revocation_reason', 'retention_until',
        'metadata', 'schema_version', 'created_at', 'updated_at',
    ];

    expect(Schema::hasTable('oauth_client_metadata'))->toBeTrue();

    foreach ($requiredColumns as $column) {
        expect(Schema::hasColumn('oauth_client_metadata', $column))
            ->toBeTrue("missing oauth_client_metadata.{$column}");
    }

    expect(tableHasUniqueIndexCovering('oauth_client_metadata', ['client_id']))->toBeTrue()
        ->and(tableHasUniqueIndexCovering('oauth_client_metadata', ['registration_access_token_hash']))->toBeTrue()
        ->and(tableHasUniqueIndexCovering('oauth_client_metadata', ['metadata_document_url_sha256']))->toBeTrue();
});

it('M3: token_endpoint_auth_method is nullable with no database default', function (): void {
    $column = collect(Schema::getColumns('oauth_client_metadata'))
        ->firstWhere('name', 'token_endpoint_auth_method');

    // MariaDB reports the SQL NULL default as the string "NULL".
    $default = $column['default'] ?? null;

    if (is_string($default) && strtoupper($default) === 'NULL') {
        $default = null;
    }

    expect($column)->not->toBeNull()
        ->and($column['nullable'] ?? null)->toBeTrue()
        ->and($default)->toBeNull();
});

it('M3: PAR and DPoP per-client flags default to false', function (): void {
    $row = OAuthClientMetadata::query()->create([
        'client_id' => (string) Str::uuid7(),
        'registration_source' => 'dcr',
        'token_endpoint_auth_method' => 'none',
    ]);

    $row->refresh();

    expect($row->require_pushed_authorization_requests)->toBeFalse()
        ->and($row->dpop_bound_access_tokens)->toBeFalse()
        ->and($row->schema_version)->toBe(1);
});

it('M6: oauth_blocked_redirect_hosts has public_id, match_mode, expiry and schema_version', function (): void {
    $requiredColumns = [
        'id', 'public_id', 'host', 'host_original', 'match_mode', 'reason',
        'expires_at', 'metadata', 'schema_version', 'created_by',
        'created_at', 'updated_at',
    ];

    expect(Schema::hasTable('oauth_blocked_redirect_hosts'))->toBeTrue();

    foreach ($requiredColumns as $column) {
        expect(Schema::hasColumn('oauth_blocked_redirect_hosts', $column))
            ->toBeTrue("missing oauth_blocked_redirect_hosts.{$column}");
    }

    $host = OAuthBlockedRedirectHost::query()->create([
        'host' => 'evil.example',
    ]);
    $host->refresh();

    expect($host->public_id)->toBeString()->not->toBeEmpty()
        ->and($host->match_mode)->toBe('host_and_subdomains')
        ->and($host->schema_version)->toBe(1)
        ->and($host->getRouteKeyName())->toBe('public_id');
});

it('M7: package UUID tables mint UUID v7 ids and carry metadata plus schema_version', function (): void {
    $client = OAuthClientMetadata::query()->create([
        'client_id' => (string) Str::uuid7(),
        'registration_source' => 'admin',
        'token_endpoint_auth_method' => 'none',
        'metadata' => ['vendor' => 'test'],
    ]);
    $consent = OAuthConsentRecord::query()->create([
        'client_id' => $client->client_id,
        'user_identifier' => (string) Str::uuid7(),
        'decision' => 'denied',
        'redirect_uri' => 'https://app.example/cb',
        'redirect_host' => 'app.example',
        'requested_scopes' => ['mcp:use'],
        'metadata' => null,
    ]);

    $client->refresh();
    $consent->refresh();

    expect($client->id)->toMatch('/^[0-9a-f-]{36}$/i')
        ->and(hexdec(substr(str_replace('-', '', $client->id), 12, 1)))->toBe(7)
        ->and($client->metadata)->toBe(['vendor' => 'test'])
        ->and($client->schema_version)->toBe(1)
        ->and($consent->id)->toMatch('/^[0-9a-f-]{36}$/i')
        ->and(hexdec(substr(str_replace('-', '', $consent->id), 12, 1)))->toBe(7)
        ->and($consent->schema_version)->toBe(1)
        ->and(Schema::hasColumn('oauth_consent_records', 'updated_at'))->toBeFalse();
});

it('S4: oauth_consent_records is append-only evidence with every consent column', function (): void {
    $requiredColumns = [
        'id', 'client_id', 'user_identifier', 'grant_id', 'decision',
        'redirect_uri', 'redirect_host', 'resource', 'requested_scopes',
        'granted_scopes', 'role', 'resources', 'all_resources', 'attributes',
        'consent_version', 'locale', 'ip_address', 'user_agent', 'correlation_id', 'resource_scopes',
        'retention_until', 'metadata', 'schema_version', 'created_at',
    ];

    expect(Schema::hasTable('oauth_consent_records'))->toBeTrue();

    foreach ($requiredColumns as $column) {
        expect(Schema::hasColumn('oauth_consent_records', $column))
            ->toBeTrue("missing oauth_consent_records.{$column}");
    }

    expect(Schema::hasColumn('oauth_consent_records', 'updated_at'))->toBeFalse();
});

it('records the grant each authorization code was consumed under', function (): void {
    expect(Schema::hasTable('oauth_auth_code_exchanges'))->toBeTrue()
        ->and(Schema::getColumnListing('oauth_auth_code_exchanges'))->toEqualCanonicalizing(['auth_code_id', 'grant_id', 'expires_at', 'user_identifier', 'metadata', 'schema_version', 'created_at']);
});

it('M7: an auth-code exchange carries metadata and schema_version 1, keyed by the code id instead of a UUID', function (): void {
    OAuthAuthCodeExchange::query()->create(['auth_code_id' => 'code-1', 'grant_id' => (string) Str::uuid7()]);
    OAuthAuthCodeExchange::query()->create([
        'auth_code_id' => 'code-2',
        'grant_id' => (string) Str::uuid7(),
        'metadata' => ['vendor' => 'test'],
    ]);

    $plain = OAuthAuthCodeExchange::query()->findOrFail('code-1');
    $withMetadata = OAuthAuthCodeExchange::query()->findOrFail('code-2');

    expect($plain->metadata)->toBeNull()
        ->and($plain->schema_version)->toBe(1)
        ->and($withMetadata->metadata)->toBe(['vendor' => 'test']);
});

it('keeps the auth-code exchange on the Passport connection, with the code row it records', function (): void {
    config()->set('passport.connection', 'passport-tenant');

    expect((new OAuthAuthCodeExchange)->getConnectionName())->toBe('passport-tenant');

    config()->set('passport.connection', null);

    expect((new OAuthAuthCodeExchange)->getConnectionName())->toBeNull();
});

it('creates the tables its Passport-connection models use on passport.connection (B2)', function (string $migrationFile, string $table): void {
    // Passport on its own database: the package tables its models read beside Passport's rows must live there too.
    config()->set('database.connections.passport_second', [
        'driver' => 'sqlite',
        'database' => ':memory:',
        'prefix' => '',
        'foreign_key_constraints' => true,
    ]);
    config()->set('passport.connection', 'passport_second');
    $migration = require __DIR__.'/../../../database/migrations/'.$migrationFile;

    // The migrator runs a migration on the connection the migration names, as `php artisan migrate` does.
    (fn (object $migrationToRun) => $this->runMigration($migrationToRun, 'up'))->call(app('migrator'), $migration);

    expect(Schema::connection('passport_second')->hasTable($table))->toBeTrue();
})->with([
    'client metadata' => ['2026_11_22_100000_create_oauth_client_metadata_table.php', 'oauth_client_metadata'],
    'auth-code exchanges' => ['2026_11_23_100300_create_oauth_auth_code_exchanges_table.php', 'oauth_auth_code_exchanges'],
]);

it('S2: CIMD runtime is off by default while schema columns exist', function (): void {
    expect(config('mcp-oauth.cimd.enabled'))->toBeFalse()
        ->and(Schema::hasColumn('oauth_client_metadata', 'metadata_document_url'))->toBeTrue()
        ->and(Schema::hasColumn('oauth_client_metadata', 'metadata_document_url_sha256'))->toBeTrue();
});

it('loads core migrations by default and keeps the mcp-oauth-migrations publish tag', function (): void {
    $providerSource = file_get_contents(
        dirname(__DIR__, 3).'/src/McpOAuthServiceProvider.php',
    );

    expect(config('mcp-oauth.migrations.load'))->toBeTrue()
        ->and($providerSource)->toContain('loadMigrationsFrom')
        ->and($providerSource)->toContain('mcp-oauth.migrations.load')
        ->and($providerSource)->toContain("'mcp-oauth-migrations'")
        ->and($providerSource)->toContain('publishesMigrations');

    $migrator = app('migrator');
    $packageMigrationsPath = realpath(dirname(__DIR__, 3).'/database/migrations');

    expect($packageMigrationsPath)->not->toBeFalse()
        ->and(collect($migrator->paths())->map(realpath(...))->contains($packageMigrationsPath))->toBeTrue();
});

/**
 * @return list<string>
 */
function tableNamesCreatedByMigrationsIn(string $directory): array
{
    $tableNames = [];

    foreach (glob($directory.'/*.php') ?: [] as $migrationFile) {
        $source = file_get_contents($migrationFile) ?: '';

        if (preg_match_all("/Schema::create\\('([^']+)'/", $source, $matches) === false) {
            continue;
        }

        foreach ($matches[1] as $tableName) {
            $tableNames[] = $tableName;
        }
    }

    return array_values(array_unique($tableNames));
}

it('S9: no package table name collides with any Passport 13 table', function (): void {
    $packageMigrationsDirectory = dirname(__DIR__, 3).'/database/migrations';
    $packageTables = tableNamesCreatedByMigrationsIn($packageMigrationsDirectory);
    $passportTables = tableNamesCreatedByMigrationsIn(
        dirname(__DIR__, 3).'/vendor/laravel/passport/database/migrations',
    );
    $reservedPassportTables = array_values(array_unique([
        ...$passportTables,
        'oauth_personal_access_clients',
    ]));

    expect($packageTables)->not->toBeEmpty()
        ->and($passportTables)->not->toBeEmpty()
        ->and(array_intersect($packageTables, $reservedPassportTables))->toBe([]);

    foreach ($packageTables as $table) {
        expect(Schema::hasTable($table))->toBeTrue();
    }

    foreach ($reservedPassportTables as $table) {
        expect(Schema::hasTable($table))->toBeFalse("must not create Passport table {$table}");
    }

    $alteredPassportTables = [];

    foreach (glob($packageMigrationsDirectory.'/*.php') ?: [] as $migrationFile) {
        $source = file_get_contents($migrationFile) ?: '';

        if (preg_match_all("/Schema::table\\('([^']+)'/", $source, $matches) === false) {
            continue;
        }

        foreach ($matches[1] as $tableName) {
            if (in_array($tableName, $reservedPassportTables, true)) {
                $alteredPassportTables[] = $tableName;
            }
        }
    }

    expect($alteredPassportTables)->toBe([]);
});

it('S4: oauth_consent_records Eloquent model refuses update and delete', function (): void {
    $consent = OAuthConsentRecord::query()->create([
        'client_id' => (string) Str::uuid7(),
        'user_identifier' => (string) Str::uuid7(),
        'decision' => 'approved',
        'redirect_uri' => 'https://app.example/cb',
        'redirect_host' => 'app.example',
        'requested_scopes' => ['mcp:use'],
        'created_at' => now(),
    ]);

    expect(fn () => $consent->update(['decision' => 'denied']))
        ->toThrow(LogicException::class)
        ->and(fn () => $consent->delete())
        ->toThrow(LogicException::class);
});
