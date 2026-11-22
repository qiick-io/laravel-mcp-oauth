<?php

declare(strict_types=1);

use Illuminate\Http\Request;
use Laravel\Passport\Passport;
use Qiick\McpOAuth\McpOAuthReadiness;
use Qiick\McpOAuth\McpOAuthServer;
use Qiick\McpOAuth\Testing\FakeAdminSwitch;

function makeServer(bool $configEnabled, bool $adminEnabled, mixed $mcpEnabled = true): McpOAuthServer
{
    config()->set('mcp-oauth.enabled', $configEnabled);
    config()->set('mcp-oauth.mcp_enabled', $mcpEnabled);
    config()->set('app.url', 'https://mcp-oauth.test');

    return new McpOAuthServer(config(), new FakeAdminSwitch($adminEnabled));
}

it('is off unless config, admin switch and product MCP flag are all true', function (): void {
    expect(makeServer(false, true)->isEnabled())->toBeFalse()
        ->and(makeServer(true, false)->isEnabled())->toBeFalse()
        ->and(makeServer(true, true, false)->isEnabled())->toBeFalse()
        ->and(makeServer(true, true, true)->isEnabled())->toBeTrue()
        ->and(makeServer(true, true, null)->isEnabled())->toBeFalse();
});

it('treats an unreadable admin switch store as off', function (): void {
    config()->set('mcp-oauth.enabled', true);
    config()->set('mcp-oauth.mcp_enabled', true);

    $server = new McpOAuthServer(
        config(),
        new FakeAdminSwitch(isEnabled: true, storeIsUnreadable: true),
    );

    expect($server->isEnabled())->toBeFalse();
});

it('treats a throwing admin switch as off (S11)', function (): void {
    config()->set('mcp-oauth.enabled', true);
    config()->set('mcp-oauth.mcp_enabled', true);

    $server = new McpOAuthServer(
        config(),
        new FakeAdminSwitch(isEnabled: true, throwsOnRead: true),
    );

    expect($server->isEnabled())->toBeFalse();
});

it('treats a half-set env key pair as missing', function (): void {
    config()->set('passport.private_key', "-----BEGIN RSA PRIVATE KEY-----\nenv\n-----END RSA PRIVATE KEY-----");
    config()->set('passport.public_key', null);

    expect(makeServer(true, true)->hasPassportKeys())->toBeFalse();

    config()->set('passport.private_key', null);
    config()->set('passport.public_key', "-----BEGIN PUBLIC KEY-----\nenv\n-----END PUBLIC KEY-----");

    expect(makeServer(true, true)->hasPassportKeys())->toBeFalse();

    config()->set('passport.private_key', null);
    config()->set('passport.public_key', null);
});

it('treats world-readable key files as missing', function (): void {
    config()->set('passport.private_key', null);
    config()->set('passport.public_key', null);

    $privatePath = Passport::keyPath('oauth-private.key');
    $publicPath = Passport::keyPath('oauth-public.key');
    @mkdir(dirname($privatePath), 0777, true);
    file_put_contents($privatePath, 'private');
    file_put_contents($publicPath, 'public');
    chmod($privatePath, 0644);
    chmod($publicPath, 0644);

    try {
        expect(makeServer(true, true)->hasPassportKeys())->toBeFalse();
    } finally {
        @unlink($privatePath);
        @unlink($publicPath);
    }
});

it('builds issuer and resource from APP_URL, never the request Host', function (): void {
    $server = makeServer(true, true);
    Request::create('https://evil.example/mcp', 'GET', server: ['HTTP_HOST' => 'evil.example']);

    expect($server->issuer())->toBe('https://mcp-oauth.test')
        ->and($server->resourceIdentifier())->toBe('https://mcp-oauth.test/mcp')
        ->and($server->acceptsResource('https://mcp-oauth.test/mcp'))->toBeTrue()
        ->and($server->acceptsResource('https://MCP-OAUTH.TEST/mcp'))->toBeTrue()
        ->and($server->acceptsResource('https://evil.example/mcp'))->toBeFalse()
        ->and($server->protectedResourceMetadataUrl())->toBe(
            'https://mcp-oauth.test/.well-known/oauth-protected-resource/mcp',
        );
});

it('normalises a trailing slash in mcp_path', function (): void {
    config()->set('mcp-oauth.mcp_path', '/mcp/');

    expect(makeServer(true, true)->resourceIdentifier())->toBe('https://mcp-oauth.test/mcp');
});

it('reports passport_keys only while OAuth is enabled', function (): void {
    $off = makeServer(false, false);
    expect((new McpOAuthReadiness($off))->checks())->toBe([]);

    config()->set('passport.private_key', null);
    config()->set('passport.public_key', null);
    $failing = makeServer(true, true);
    expect((new McpOAuthReadiness($failing))->checks())->toBe(['passport_keys' => 'fail']);

    config()->set('passport.private_key', "-----BEGIN RSA PRIVATE KEY-----\na\n-----END RSA PRIVATE KEY-----");
    config()->set('passport.public_key', "-----BEGIN PUBLIC KEY-----\nb\n-----END PUBLIC KEY-----");
    $ready = makeServer(true, true);
    expect((new McpOAuthReadiness($ready))->checks())->toBe(['passport_keys' => 'ok']);

    config()->set('passport.private_key', null);
    config()->set('passport.public_key', null);
});

it('accepts a complete env key pair and rejects empty strings', function (): void {
    config()->set('passport.private_key', "-----BEGIN RSA PRIVATE KEY-----\na\n-----END RSA PRIVATE KEY-----");
    config()->set('passport.public_key', "-----BEGIN PUBLIC KEY-----\nb\n-----END PUBLIC KEY-----");
    expect(makeServer(true, true)->hasPassportKeys())->toBeTrue();

    config()->set('passport.private_key', '');
    config()->set('passport.public_key', '');
    expect(makeServer(true, true)->hasPassportKeys())->toBeFalse();

    config()->set('passport.private_key', null);
    config()->set('passport.public_key', null);
});

it('resolves mcp_enabled from a config key string or a closure', function (): void {
    config()->set('product.mcp', true);
    expect(makeServer(true, true, 'product.mcp')->isEnabled())->toBeTrue();

    config()->set('product.mcp', false);
    expect(makeServer(true, true, 'product.mcp')->isEnabled())->toBeFalse();

    expect(makeServer(true, true, static fn (): bool => true)->isEnabled())->toBeTrue()
        ->and(makeServer(true, true, static fn (): bool => false)->isEnabled())->toBeFalse();
});

it('is ready only when enabled, keys exist and app.url is absolute', function (): void {
    config()->set('passport.private_key', null);
    config()->set('passport.public_key', null);
    expect(makeServer(true, true)->isReady())->toBeFalse();

    config()->set('passport.private_key', "-----BEGIN RSA PRIVATE KEY-----\na\n-----END RSA PRIVATE KEY-----");
    config()->set('passport.public_key', "-----BEGIN PUBLIC KEY-----\nb\n-----END PUBLIC KEY-----");
    $ready = makeServer(true, true);
    expect($ready->isReady())->toBeTrue()
        ->and(makeServer(false, true)->isReady())->toBeFalse();

    config()->set('app.url', 'mcp-oauth.test');
    expect($ready->isReady())->toBeFalse();

    config()->set('app.url', 'https://mcp-oauth.test');
    config()->set('passport.private_key', null);
    config()->set('passport.public_key', null);
});

it('exposes wire scope, grant types, challenge methods and TTLs', function (): void {
    $server = makeServer(true, true);

    expect($server::WIRE_SCOPE)->toBe('mcp:use')
        ->and($server::SUPPORTED_GRANT_TYPES)->toBe(['authorization_code', 'refresh_token'])
        ->and($server::SUPPORTED_CODE_CHALLENGE_METHODS)->toBe(['S256'])
        ->and($server->scopeDescriptions())->toHaveKey('mcp:use')
        ->and($server->accessTokenLifetime()->format('%i'))->toBe('60')
        ->and($server->refreshTokenLifetime()->format('%d'))->toBe('30');
});

it('accepts mode-600, 440 and 660 key files as usable', function (int $mode): void {
    config()->set('passport.private_key', null);
    config()->set('passport.public_key', null);

    $privatePath = Passport::keyPath('oauth-private.key');
    $publicPath = Passport::keyPath('oauth-public.key');
    @mkdir(dirname($privatePath), 0777, true);
    @chmod($privatePath, 0600);
    @chmod($publicPath, 0600);
    file_put_contents($privatePath, 'private');
    file_put_contents($publicPath, 'public');
    chmod($privatePath, $mode);
    chmod($publicPath, $mode);

    try {
        expect(makeServer(true, true)->hasPassportKeys())->toBeTrue();
    } finally {
        @chmod($privatePath, 0600);
        @chmod($publicPath, 0600);
        @unlink($privatePath);
        @unlink($publicPath);
    }
})->with([
    '600' => [0600],
    '440' => [0440],
    '660' => [0660],
]);
