<?php

declare(strict_types=1);

it('merges the package defaults into the mcp-oauth config', function (): void {
    expect(config('mcp-oauth.enabled'))->toBeFalse();
    expect(config('mcp-oauth.mcp_enabled'))->toBeNull();
    expect(config('mcp-oauth.mcp_path'))->toBe('mcp');
    expect(config('mcp-oauth.access_token_ttl_minutes'))->toBe('60');
    expect(config('mcp-oauth.refresh_token_ttl_days'))->toBe('30');
    expect(config('mcp-oauth.auth_code_ttl_minutes'))->toBe('10');
    expect(config('mcp-oauth.registrations_per_minute'))->toBe('10');
    expect(config('mcp-oauth.registrations_global_cap'))->toBe(10000);
    expect(config('mcp-oauth.unused_client_retention_hours'))->toBe(24);
    expect(config('mcp-oauth.revoked_retention_days'))->toBe(90);
    expect(config('mcp-oauth.spec_revision'))->toBe('2026-07-28');
    expect(config('mcp-oauth.cimd.enabled'))->toBeFalse();
    expect(config('mcp-oauth.cimd.max_document_bytes'))->toBe(65536);
    expect(config('mcp-oauth.token_requests_per_minute'))->toBe('60');
    expect(config('mcp-oauth.mcp_auth_failures_per_minute'))->toBe(20);
    expect(config('mcp-oauth.host_block_chunk_size'))->toBe(100);
    expect(config('mcp-oauth.grant_binding_column'))->toBe('api_key_id');
    expect(config('mcp-oauth.user_model'))->toBeNull();
    expect(config('mcp-oauth.migrations.load'))->toBeTrue();
});

it('lets an app publish the config file', function (): void {
    $this->artisan('vendor:publish', ['--tag' => 'mcp-oauth-config', '--force' => true])
        ->assertSuccessful();

    expect(config_path('mcp-oauth.php'))->toBeFile();

    unlink(config_path('mcp-oauth.php'));
});

it('lets an app publish migrations under mcp-oauth-migrations', function (): void {
    $this->artisan('vendor:publish', ['--tag' => 'mcp-oauth-migrations', '--force' => true])
        ->assertSuccessful();

    $published = database_path('migrations');
    $migrationFiles = glob($published.'/*_create_oauth_*_table.php') ?: [];

    expect($migrationFiles)->toHaveCount(3);

    foreach ($migrationFiles as $migrationFile) {
        unlink($migrationFile);
    }
});
