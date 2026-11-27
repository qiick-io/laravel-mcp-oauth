<?php

declare(strict_types=1);

use Illuminate\Support\ServiceProvider;
use Qiick\McpOAuth\Contracts\ClientMetadataDocumentFetcherContract;
use Qiick\McpOAuth\Exceptions\InvalidMcpOAuthConfigException;
use Qiick\McpOAuth\Internal\OutboundClientMetadataDocumentFetcher;
use Qiick\McpOAuth\McpOAuthServiceProvider;

it('merges the package defaults into the mcp-oauth config', function (): void {
    expect(config('mcp-oauth.enabled'))->toBeFalse();
    expect(config('mcp-oauth.mcp_enabled'))->toBeNull();
    expect(config('mcp-oauth.mcp_path'))->toBe('mcp');
    expect(config('mcp-oauth.access_token_ttl_minutes'))->toBe('60');
    expect(config('mcp-oauth.refresh_token_ttl_days'))->toBe('30');
    expect(config('mcp-oauth.auth_code_ttl_minutes'))->toBe('10');
    expect(config('mcp-oauth.registrations_per_minute'))->toBe('10');
    expect(config('mcp-oauth.authorize_requests_per_minute'))->toBe('30');
    expect(config('mcp-oauth.authorize_requests_per_client_per_minute'))->toBe('20');
    expect(config('mcp-oauth.token_requests_per_minute'))->toBe('60');
    expect(config('mcp-oauth.token_requests_per_client_per_minute'))->toBe('30');
    expect(config('mcp-oauth.revoke_requests_per_minute'))->toBe('30');
    expect(config('mcp-oauth.revoke_requests_per_client_per_minute'))->toBe('20');
    expect(config('mcp-oauth.registrations_global_cap'))->toBe('10000');
    expect(config('mcp-oauth.unused_client_retention_hours'))->toBe('24');
    expect(config('mcp-oauth.revoked_retention_days'))->toBe('90');
    expect(config('mcp-oauth.spec_revision'))->toBe('2026-07-28');
    expect(config('mcp-oauth.cimd.enabled'))->toBeFalse();
    expect(config('mcp-oauth.cimd.max_document_bytes'))->toBe('65536');
    expect(config('mcp-oauth.mcp_auth_failures_per_minute'))->toBe('20');
    expect(config('mcp-oauth.host_block_chunk_size'))->toBe(100);
    expect(config('mcp-oauth.grant_binding_column'))->toBe('api_key_id');
    expect(config('mcp-oauth.user_model'))->toBeNull();
    expect(config('mcp-oauth.migrations.load'))->toBeTrue();
});

it('binds the isolated Outbound fetcher only when CIMD is enabled', function (): void {
    expect(app()->bound(ClientMetadataDocumentFetcherContract::class))->toBeFalse();

    config()->set('mcp-oauth.cimd.enabled', true);
    (new McpOAuthServiceProvider($this->app))->boot();

    expect(app(ClientMetadataDocumentFetcherContract::class))->toBeInstanceOf(OutboundClientMetadataDocumentFetcher::class);
});

it('refuses to boot with an invalid CIMD switch', function (): void {
    config()->set('mcp-oauth.cimd.enabled', 'invalid');

    expect(fn () => (new McpOAuthServiceProvider($this->app))->boot())
        ->toThrow(InvalidMcpOAuthConfigException::class, 'cimd.enabled');
});

it('lets an app publish the config file', function (): void {
    // The mapping, not a real publish: writing into Testbench's shared
    // skeleton raced with parallel workers loading their config from it.
    $publishedFiles = ServiceProvider::pathsToPublish(McpOAuthServiceProvider::class, 'mcp-oauth-config');

    expect(array_values($publishedFiles))->toBe([config_path('mcp-oauth.php')])
        ->and((string) array_key_first($publishedFiles))->toBeFile();
});

it('lets an app publish migrations under mcp-oauth-migrations', function (): void {
    $this->artisan('vendor:publish', ['--tag' => 'mcp-oauth-migrations', '--force' => true])
        ->assertSuccessful();

    $published = database_path('migrations');
    $migrationFiles = glob($published.'/*_create_oauth_*_table.php') ?: [];

    expect($migrationFiles)->toHaveCount(4);

    foreach ($migrationFiles as $migrationFile) {
        unlink($migrationFile);
    }
});

it('pins laravel/mcp\'s authorization server to the issuer, unless the product set one (S13)', function (?string $configured, string $expected): void {
    config()->set('app.url', 'https://mcp-oauth.test/');
    config()->set('mcp.authorization_server', $configured);

    (new McpOAuthServiceProvider($this->app))->boot();

    // Mcp::oauthRoutes() would otherwise fall back to url('/'), the request Host.
    expect(config('mcp.authorization_server'))->toBe($expected);
})->with([
    'unset' => [null, 'https://mcp-oauth.test'],
    'set by the product' => ['https://auth.example', 'https://auth.example'],
]);
