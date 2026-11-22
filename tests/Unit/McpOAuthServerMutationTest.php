<?php

declare(strict_types=1);

use Laravel\Passport\Passport;
use Qiick\McpOAuth\McpOAuthServer;
use Qiick\McpOAuth\Testing\FakeAdminSwitch;

function mutationServer(
    bool $configEnabled = true,
    bool $adminEnabled = true,
    mixed $mcpEnabled = true,
    bool $skipUnixKeyModes = false,
): McpOAuthServer {
    config()->set('mcp-oauth.enabled', $configEnabled);
    config()->set('mcp-oauth.mcp_enabled', $mcpEnabled);
    config()->set('app.url', 'https://mcp-oauth.test');

    return new McpOAuthServer(config(), new FakeAdminSwitch($adminEnabled), $skipUnixKeyModes);
}

it('freezes the wire grant and challenge constants', function (): void {
    expect(McpOAuthServer::SUPPORTED_GRANT_TYPES)->toBe(['authorization_code', 'refresh_token'])
        ->and(McpOAuthServer::SUPPORTED_CODE_CHALLENGE_METHODS)->toBe(['S256'])
        ->and(array_keys(mutationServer()->scopeDescriptions()))->toBe(['mcp:use']);
});

it('treats a missing mcp-oauth.enabled config default as off', function (): void {
    config()->set('mcp-oauth.mcp_enabled', true);
    config()->offsetUnset('mcp-oauth.enabled');

    expect((new McpOAuthServer(config(), new FakeAdminSwitch(true)))->isEnabled())->toBeFalse();
});

it('treats string zero enabled config as off via bool cast', function (): void {
    config()->set('mcp-oauth.enabled', '0');
    config()->set('mcp-oauth.mcp_enabled', true);

    expect((new McpOAuthServer(config(), new FakeAdminSwitch(true)))->isEnabled())->toBeFalse();
});

it('requires both env PEMs to be non-empty strings', function (): void {
    config()->set('passport.private_key', '');
    config()->set('passport.public_key', "-----BEGIN PUBLIC KEY-----\nb\n-----END PUBLIC KEY-----");
    expect(mutationServer()->hasPassportKeys())->toBeFalse();

    config()->set('passport.private_key', "-----BEGIN RSA PRIVATE KEY-----\na\n-----END RSA PRIVATE KEY-----");
    config()->set('passport.public_key', '');
    expect(mutationServer()->hasPassportKeys())->toBeFalse();

    config()->set('passport.private_key', "-----BEGIN RSA PRIVATE KEY-----\na\n-----END RSA PRIVATE KEY-----");
    config()->set('passport.public_key', "-----BEGIN PUBLIC KEY-----\nb\n-----END PUBLIC KEY-----");
    expect(mutationServer()->hasPassportKeys())->toBeTrue();
});

it('does not fall through to key files when only one env PEM is set', function (): void {
    $privatePath = Passport::keyPath('oauth-private.key');
    $publicPath = Passport::keyPath('oauth-public.key');
    @mkdir(dirname($privatePath), 0777, true);
    @chmod($privatePath, 0600);
    @chmod($publicPath, 0600);
    file_put_contents($privatePath, 'private');
    file_put_contents($publicPath, 'public');
    chmod($privatePath, 0600);
    chmod($publicPath, 0600);

    try {
        config()->set('passport.private_key', "-----BEGIN RSA PRIVATE KEY-----\na\n-----END RSA PRIVATE KEY-----");
        config()->set('passport.public_key', '');
        expect(mutationServer()->hasPassportKeys())->toBeFalse();

        config()->set('passport.private_key', '');
        config()->set('passport.public_key', "-----BEGIN PUBLIC KEY-----\nb\n-----END PUBLIC KEY-----");
        expect(mutationServer()->hasPassportKeys())->toBeFalse();
    } finally {
        @chmod($privatePath, 0600);
        @chmod($publicPath, 0600);
        @unlink($privatePath);
        @unlink($publicPath);
        config()->set('passport.private_key', null);
        config()->set('passport.public_key', null);
    }
});

it('requires both key files to be usable together', function (): void {
    config()->set('passport.private_key', null);
    config()->set('passport.public_key', null);

    $privatePath = Passport::keyPath('oauth-private.key');
    $publicPath = Passport::keyPath('oauth-public.key');
    @mkdir(dirname($privatePath), 0777, true);
    @chmod($privatePath, 0600);
    @chmod($publicPath, 0600);
    file_put_contents($privatePath, 'private');
    file_put_contents($publicPath, 'public');
    chmod($privatePath, 0600);
    chmod($publicPath, 0644);

    try {
        expect(mutationServer()->hasPassportKeys())->toBeFalse();
    } finally {
        @chmod($privatePath, 0600);
        @chmod($publicPath, 0600);
        @unlink($privatePath);
        @unlink($publicPath);
    }
});

it('treats a missing key file as unusable', function (): void {
    config()->set('passport.private_key', null);
    config()->set('passport.public_key', null);

    $privatePath = Passport::keyPath('oauth-private.key');
    $publicPath = Passport::keyPath('oauth-public.key');
    @chmod($privatePath, 0600);
    @chmod($publicPath, 0600);
    @unlink($privatePath);
    @unlink($publicPath);

    expect(mutationServer()->hasPassportKeys())->toBeFalse();
});

it('accepts every allowed unix mode including 400', function (int $mode): void {
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
        expect(mutationServer()->hasPassportKeys())->toBeTrue();
    } finally {
        @chmod($privatePath, 0600);
        @chmod($publicPath, 0600);
        @unlink($privatePath);
        @unlink($publicPath);
    }
})->with([
    '400' => [0400],
    '440' => [0440],
    '600' => [0600],
    '640' => [0640],
    '660' => [0660],
]);

it('skips unix mode checks when constructed for Windows', function (): void {
    config()->set('passport.private_key', null);
    config()->set('passport.public_key', null);

    $privatePath = Passport::keyPath('oauth-private.key');
    $publicPath = Passport::keyPath('oauth-public.key');
    @mkdir(dirname($privatePath), 0777, true);
    @chmod($privatePath, 0600);
    @chmod($publicPath, 0600);
    file_put_contents($privatePath, 'private');
    file_put_contents($publicPath, 'public');
    chmod($privatePath, 0644);
    chmod($publicPath, 0644);

    try {
        expect(mutationServer(skipUnixKeyModes: true)->hasPassportKeys())->toBeTrue()
            ->and(mutationServer(skipUnixKeyModes: false)->hasPassportKeys())->toBeFalse();
    } finally {
        @chmod($privatePath, 0600);
        @chmod($publicPath, 0600);
        @unlink($privatePath);
        @unlink($publicPath);
    }
});

it('trims trailing slashes from issuer and resource comparisons', function (): void {
    $server = mutationServer();
    config()->set('app.url', 'https://mcp-oauth.test/');

    expect($server->issuer())->toBe('https://mcp-oauth.test')
        ->and($server->acceptsResource('https://mcp-oauth.test/mcp/'))->toBeTrue()
        ->and($server->acceptsResource(null))->toBeFalse()
        ->and($server->acceptsResource(12))->toBeFalse();
});

it('falls back mcp_path when empty or non-string and strips leading slashes', function (): void {
    config()->set('mcp-oauth.mcp_path', '');
    expect(mutationServer()->resourceIdentifier())->toBe('https://mcp-oauth.test/mcp');

    config()->set('mcp-oauth.mcp_path', '/nested/mcp');
    expect(mutationServer()->resourceIdentifier())->toBe('https://mcp-oauth.test/nested/mcp')
        ->and(mutationServer()->protectedResourceMetadataUrl())->toBe(
            'https://mcp-oauth.test/.well-known/oauth-protected-resource/nested/mcp',
        );

    config()->set('mcp-oauth.mcp_path', 12);
    expect(mutationServer()->resourceIdentifier())->toBe('https://mcp-oauth.test/mcp');

    config()->set('mcp-oauth.mcp_path', 'mcp');
});

it('floors TTLs at one and ignores non-integer config', function (): void {
    config()->set('mcp-oauth.access_token_ttl_minutes', 0);
    config()->set('mcp-oauth.refresh_token_ttl_days', 0);
    $zeroed = mutationServer();
    expect($zeroed->accessTokenLifetime()->format('%i'))->toBe('1')
        ->and($zeroed->refreshTokenLifetime()->format('%d'))->toBe('1');

    config()->set('mcp-oauth.access_token_ttl_minutes', '60');
    config()->set('mcp-oauth.refresh_token_ttl_days', '30');
    $strings = mutationServer();
    expect($strings->accessTokenLifetime()->format('%i'))->toBe('60')
        ->and($strings->refreshTokenLifetime()->format('%d'))->toBe('30');

    config()->set('mcp-oauth.access_token_ttl_minutes', 60);
    config()->set('mcp-oauth.refresh_token_ttl_days', 30);
});

it('reads a product MCP flag config key with a false default when the key is missing', function (): void {
    config()->offsetUnset('product.missing.flag');

    expect(mutationServer(mcpEnabled: 'product.missing.flag')->isEnabled())->toBeFalse();
});

it('casts closure and config-key results through bool', function (): void {
    expect(mutationServer(mcpEnabled: static fn (): int => 0)->isEnabled())->toBeFalse()
        ->and(mutationServer(mcpEnabled: static fn (): int => 1)->isEnabled())->toBeTrue();

    // (bool) '0' === false in PHP; string "0" must not count as enabled.
    config()->set('product.flag', '0');
    expect(mutationServer(mcpEnabled: 'product.flag')->isEnabled())->toBeFalse();

    config()->set('product.flag', '1');
    expect(mutationServer(mcpEnabled: 'product.flag')->isEnabled())->toBeTrue();

    config()->set('product.flag', '');
    expect(mutationServer(mcpEnabled: 'product.flag')->isEnabled())->toBeFalse();
});

it('rejects an empty string mcp_enabled gate as unset', function (): void {
    expect(mutationServer(mcpEnabled: '')->isEnabled())->toBeFalse();
});

it('returns empty issuer when app.url is not a string', function (): void {
    $server = mutationServer();
    config()->set('app.url', null);

    expect($server->issuer())->toBe('');
});
