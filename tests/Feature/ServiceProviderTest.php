<?php

declare(strict_types=1);

it('merges the package defaults into the mcp-oauth config', function (): void {
    expect(config('mcp-oauth.enabled'))->toBeFalse();
    expect(config('mcp-oauth.mcp_enabled'))->toBeNull();
    expect(config('mcp-oauth.mcp_path'))->toBe('mcp');
    expect(config('mcp-oauth.access_token_ttl_minutes'))->toBe(60);
    expect(config('mcp-oauth.refresh_token_ttl_days'))->toBe(30);
    expect(config('mcp-oauth.registrations_per_minute'))->toBe(10);
    expect(config('mcp-oauth.registrations_global_cap'))->toBe(10000);
    expect(config('mcp-oauth.unused_client_retention_hours'))->toBe(24);
    expect(config('mcp-oauth.token_requests_per_minute'))->toBe(60);
    expect(config('mcp-oauth.mcp_auth_failures_per_minute'))->toBe(20);
    expect(config('mcp-oauth.host_block_chunk_size'))->toBe(100);
    expect(config('mcp-oauth.grant_binding_column'))->toBe('api_key_id');
    expect(config('mcp-oauth.user_model'))->toBeNull();
});

it('lets an app publish the config file', function (): void {
    $this->artisan('vendor:publish', ['--tag' => 'mcp-oauth-config', '--force' => true])
        ->assertSuccessful();

    expect(config_path('mcp-oauth.php'))->toBeFile();

    unlink(config_path('mcp-oauth.php'));
});
