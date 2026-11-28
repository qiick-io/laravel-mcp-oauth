<?php

declare(strict_types=1);

use Qiick\McpOAuth\Exceptions\InvalidMcpOAuthConfigException;
use Qiick\McpOAuth\McpOAuthServer;
use Qiick\McpOAuth\McpOAuthServiceProvider;
use Qiick\McpOAuth\Tests\Support\TestUser;

it('fills missing keys in older published sections and keeps their overrides', function (): void {
    $shipped = require __DIR__.'/../../config/mcp-oauth.php';
    $published = $shipped;
    $published['cimd'] = ['enabled' => false, 'max_document_bytes' => '2048'];
    $published['companion'] = ['grant_max_age_days' => '21'];
    $published['retention'] = [];
    $published['migrations'] = [];
    config()->set('mcp-oauth', $published);

    $provider = new McpOAuthServiceProvider($this->app);
    $provider->register();
    $provider->boot();

    expect(config('mcp-oauth.cimd.max_document_bytes'))->toBe('2048')
        ->and(config('mcp-oauth.cimd.timeout_seconds'))->toBe($shipped['cimd']['timeout_seconds'])
        ->and(config('mcp-oauth.cimd.cache_min_seconds'))->toBe($shipped['cimd']['cache_min_seconds'])
        ->and(config('mcp-oauth.cimd.cache_max_seconds'))->toBe($shipped['cimd']['cache_max_seconds'])
        ->and(config('mcp-oauth.companion.grant_max_age_days'))->toBe('21')
        ->and(config('mcp-oauth.companion.enabled'))->toBe($shipped['companion']['enabled'])
        ->and(config('mcp-oauth.retention.schedule'))->toBe($shipped['retention']['schedule'])
        ->and(config('mcp-oauth.migrations.load'))->toBe($shipped['migrations']['load']);
});

it('rejects a present invalid section by name', function (string $section): void {
    $provider = new McpOAuthServiceProvider($this->app);
    config()->set($section, null);

    expect(function () use ($provider): void {
        $provider->register();
        $provider->boot();
    })->toThrow(InvalidMcpOAuthConfigException::class, $section);
})->with(['mcp-oauth', 'mcp-oauth.cimd', 'mcp-oauth.companion', 'mcp-oauth.retention', 'mcp-oauth.migrations']);

it('rejects a present invalid boolean by name during boot', function (string $key): void {
    config()->set('mcp-oauth.'.$key, 'misspelled');

    expect(fn () => (new McpOAuthServiceProvider($this->app))->boot())
        ->toThrow(InvalidMcpOAuthConfigException::class, $key);
})->with(['enabled', 'migrations.load', 'revocation_enabled', 'retention.schedule', 'cimd.enabled', 'companion.enabled']);

it('normalizes supplied boolean switches and preserves product adapters', function (): void {
    $switches = [
        'enabled' => ['off', false],
        'companion.enabled' => ['0', false],
        'cimd.enabled' => ['yes', true],
        'revocation_enabled' => ['no', false],
        'retention.schedule' => ['on', true],
        'migrations.load' => ['false', false],
    ];
    $productGate = static fn (): bool => true;
    config()->set('mcp-oauth.mcp_enabled', $productGate);
    config()->set('mcp-oauth.user_model', TestUser::class);

    foreach ($switches as $key => [$configuredValue]) {
        config()->set('mcp-oauth.'.$key, $configuredValue);
    }

    (new McpOAuthServiceProvider($this->app))->boot();

    foreach ($switches as $key => [, $expectedValue]) {
        expect(config('mcp-oauth.'.$key))->toBe($expectedValue);
    }

    expect(config('mcp-oauth.mcp_enabled'))->toBe($productGate)
        ->and(config('mcp-oauth.user_model'))->toBe(TestUser::class);
});

it('preserves the documented MCP resource fallback for a root or empty path', function (string $path): void {
    config()->set('mcp-oauth.mcp_path', $path);

    (new McpOAuthServiceProvider($this->app))->boot();

    $server = $this->app->make(McpOAuthServer::class);
    expect($server->resourceIdentifier())->toBe(rtrim(config('app.url'), '/').'/mcp');
})->with(['/', '']);

it('rejects invalid package values before boot completes', function (string $key, mixed $value): void {
    config()->set('mcp-oauth.'.$key, $value);

    expect(fn () => (new McpOAuthServiceProvider($this->app))->boot())
        ->toThrow(InvalidMcpOAuthConfigException::class, $key);
})->with([
    'empty switch' => ['enabled', ''],
    'whitespace-only switch' => ['enabled', ' '],
    'resource path' => ['mcp_path', '/?query=value'],
    'non-string resource path' => ['mcp_path', ['mcp']],
    'resource path with a backslash' => ['mcp_path', '/first\\second'],
    'product gate' => ['mcp_enabled', []],
    'blank product gate' => ['mcp_enabled', ' '],
    'chunk size' => ['host_block_chunk_size', 0],
    'binding column' => ['grant_binding_column', false],
    'user model' => ['user_model', stdClass::class],
    'spec revision' => ['spec_revision', 'invalid'],
]);
