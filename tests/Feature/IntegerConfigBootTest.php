<?php

declare(strict_types=1);

use Qiick\McpOAuth\Exceptions\InvalidMcpOAuthConfigException;
use Qiick\McpOAuth\Internal\BoundedPositiveInt;
use Qiick\McpOAuth\McpOAuthServiceProvider;

/**
 * Design §6: every integer key fails closed at boot. `(int) env()` in the
 * config file would turn `1e3` into 1000 and `abc` into 0 before validation
 * ever sees the value, so the file must hand over the raw env string.
 */
dataset('integer_config_keys_and_env_names', [
    'global cap' => ['registrations_global_cap', 'MCP_OAUTH_REGISTRATIONS_GLOBAL_CAP'],
    'unused client retention' => ['unused_client_retention_hours', 'MCP_OAUTH_UNUSED_CLIENT_RETENTION_HOURS'],
    'revoked retention' => ['revoked_retention_days', 'MCP_OAUTH_REVOKED_RETENTION_DAYS'],
    'CIMD document size' => ['cimd.max_document_bytes', 'MCP_OAUTH_CIMD_MAX_DOCUMENT_BYTES'],
    'CIMD timeout' => ['cimd.timeout_seconds', 'MCP_OAUTH_CIMD_TIMEOUT_SECONDS'],
    'CIMD cache minimum' => ['cimd.cache_min_seconds', 'MCP_OAUTH_CIMD_CACHE_MIN_SECONDS'],
    'CIMD cache maximum' => ['cimd.cache_max_seconds', 'MCP_OAUTH_CIMD_CACHE_MAX_SECONDS'],
    'Companion grant absolute age' => ['companion.grant_max_age_days', 'MCP_OAUTH_COMPANION_GRANT_MAX_AGE_DAYS'],
]);

it('hands the raw env string to boot validation instead of casting it', function (string $configKey, string $envName): void {
    putenv($envName.'=1e3');
    $_ENV[$envName] = '1e3';
    $_SERVER[$envName] = '1e3';

    try {
        $packageConfig = require __DIR__.'/../../config/mcp-oauth.php';

        expect(data_get($packageConfig, $configKey))->toBe('1e3');
    } finally {
        putenv($envName);
        unset($_ENV[$envName], $_SERVER[$envName]);
    }
})->with('integer_config_keys_and_env_names');

it('rejects a scientific, non-numeric, zero or oversized integer at boot', function (string $configKey): void {
    $maximumsByConfigKey = [
        'registrations_global_cap' => BoundedPositiveInt::REGISTRATIONS_GLOBAL_CAP_MAX,
        'unused_client_retention_hours' => BoundedPositiveInt::UNUSED_CLIENT_RETENTION_HOURS_MAX,
        'revoked_retention_days' => BoundedPositiveInt::REVOKED_RETENTION_DAYS_MAX,
        'cimd.max_document_bytes' => BoundedPositiveInt::CIMD_MAX_DOCUMENT_BYTES_MAX,
        'cimd.timeout_seconds' => BoundedPositiveInt::CIMD_TIMEOUT_SECONDS_MAX,
        'cimd.cache_min_seconds' => BoundedPositiveInt::CIMD_CACHE_SECONDS_MAX,
        'cimd.cache_max_seconds' => BoundedPositiveInt::CIMD_CACHE_SECONDS_MAX,
        'companion.grant_max_age_days' => BoundedPositiveInt::COMPANION_GRANT_AGE_DAYS_MAX,
    ];

    foreach (['1e3', 'abc', '1.5', 0, $maximumsByConfigKey[$configKey] + 1] as $invalidValue) {
        config(['mcp-oauth.'.$configKey => $invalidValue]);

        expect(fn () => (new McpOAuthServiceProvider($this->app))->boot())
            ->toThrow(InvalidMcpOAuthConfigException::class, $configKey);
    }
})->with('integer_config_keys_and_env_names');

it('boots with the documented maximum of every integer key', function (): void {
    config([
        'mcp-oauth.registrations_global_cap' => (string) BoundedPositiveInt::REGISTRATIONS_GLOBAL_CAP_MAX,
        'mcp-oauth.unused_client_retention_hours' => (string) BoundedPositiveInt::UNUSED_CLIENT_RETENTION_HOURS_MAX,
        'mcp-oauth.revoked_retention_days' => (string) BoundedPositiveInt::REVOKED_RETENTION_DAYS_MAX,
        'mcp-oauth.cimd.max_document_bytes' => (string) BoundedPositiveInt::CIMD_MAX_DOCUMENT_BYTES_MAX,
        'mcp-oauth.cimd.timeout_seconds' => (string) BoundedPositiveInt::CIMD_TIMEOUT_SECONDS_MAX,
        'mcp-oauth.cimd.cache_min_seconds' => (string) BoundedPositiveInt::CIMD_CACHE_SECONDS_MAX,
        'mcp-oauth.cimd.cache_max_seconds' => (string) BoundedPositiveInt::CIMD_CACHE_SECONDS_MAX,
        'mcp-oauth.companion.grant_max_age_days' => (string) BoundedPositiveInt::COMPANION_GRANT_AGE_DAYS_MAX,
    ]);

    expect(fn () => (new McpOAuthServiceProvider($this->app))->boot())->not->toThrow(InvalidMcpOAuthConfigException::class);
});

it('rejects a CIMD cache minimum above the cache maximum at boot', function (): void {
    config([
        'mcp-oauth.cimd.cache_min_seconds' => '600',
        'mcp-oauth.cimd.cache_max_seconds' => '60',
    ]);

    expect(fn () => (new McpOAuthServiceProvider($this->app))->boot())
        ->toThrow(InvalidMcpOAuthConfigException::class, 'cimd.cache_min_seconds');
});

it('boots when the CIMD cache minimum equals the maximum', function (): void {
    config([
        'mcp-oauth.cimd.cache_min_seconds' => '600',
        'mcp-oauth.cimd.cache_max_seconds' => '600',
    ]);

    expect(fn () => (new McpOAuthServiceProvider($this->app))->boot())->not->toThrow(InvalidMcpOAuthConfigException::class);
});
