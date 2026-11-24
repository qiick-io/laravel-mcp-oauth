<?php

declare(strict_types=1);

use Illuminate\Http\Request;
use Laravel\Passport\Passport;
use Qiick\McpOAuth\Exceptions\InvalidMcpOAuthConfigException;
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

it('compares the resource path exactly and scheme and host case-insensitively (RFC 8707, MCP)', function (): void {
    $server = makeServer(true, true);
    config()->set('app.url', 'https://mcp.example/API');
    config()->set('mcp-oauth.mcp_path', 'MCP');

    expect($server->resourceIdentifier())->toBe('https://mcp.example/API/MCP')
        ->and($server->acceptsResource('https://mcp.example/API/MCP'))->toBeTrue()
        ->and($server->acceptsResource('https://mcp.example/API/MCP/'))->toBeTrue()
        // MCP: implementations SHOULD accept uppercase scheme and host.
        ->and($server->acceptsResource('https://MCP.EXAMPLE/API/MCP'))->toBeTrue()
        ->and($server->acceptsResource('HTTPS://mcp.example/API/MCP'))->toBeTrue()
        ->and($server->acceptsResource('https://mcp.example/api/mcp'))->toBeFalse()
        ->and($server->acceptsResource('https://mcp.example/API/MCP//'))->toBeFalse()
        ->and($server->acceptsResource('https://mcp.example:443/API/MCP'))->toBeFalse()
        ->and($server->acceptsResource('https://mcp.example/API/MCP?x=1'))->toBeFalse()
        ->and($server->acceptsResource('https://mcp.example/API/MCP#x'))->toBeFalse()
        ->and($server->acceptsResource('https://user@mcp.example/API/MCP'))->toBeFalse()
        ->and($server->acceptsResource('https://evil.example/API/MCP'))->toBeFalse()
        ->and($server->acceptsResource('mcp.example/API/MCP'))->toBeFalse();
});

it('accepts the lower-case host when APP_URL spells it in upper case', function (): void {
    $server = makeServer(true, true);
    config()->set('app.url', 'https://MCP.Example');

    expect($server->acceptsResource('https://mcp.example/mcp'))->toBeTrue()
        ->and($server->acceptsResource('https://MCP.Example/mcp'))->toBeTrue();
});

it('falls back to the default path when mcp_path is only slashes', function (): void {
    $server = makeServer(true, true);
    config()->set('mcp-oauth.mcp_path', '/');

    expect($server->resourceIdentifier())->toBe('https://mcp-oauth.test/mcp')
        ->and($server->acceptsResource('https://mcp-oauth.test/mcp'))->toBeTrue();
});

// --- M9: the contract the discovery documents and adopters read ------------

it('pins the MCP authorization spec revision from config (M8, M9)', function (): void {
    $server = makeServer(true, true);

    expect($server->specRevision())->toBe('2026-07-28');

    config()->set('mcp-oauth.spec_revision', '2025-11-25');

    expect($server->specRevision())->toBe('2025-11-25');
});

it('fails closed on a spec revision that is not a date', function (mixed $specRevision): void {
    $server = makeServer(true, true);
    config()->set('mcp-oauth.spec_revision', $specRevision);

    expect(fn (): string => $server->specRevision())
        ->toThrow(InvalidMcpOAuthConfigException::class, 'spec_revision');
})->with([
    'empty' => [''],
    'null' => [null],
    'not a date' => ['latest'],
    'a date with a suffix' => ['2026-07-28-draft'],
    'a date with a prefix' => ['v2026-07-28'],
    'a date with a trailing newline' => ["2026-07-28\n"],
]);

it('advertises the revocation endpoint from APP_URL and no client ID metadata documents', function (): void {
    $server = makeServer(true, true);

    expect($server->revocationEndpointUrl())->toBe('https://mcp-oauth.test/oauth/revoke')
        ->and($server->supportsClientIdMetadataDocuments())->toBeFalse();

    config()->set('mcp-oauth.cimd.enabled', true);

    // No fetcher yet: switching CIMD on must not make the metadata claim it.
    expect($server->supportsClientIdMetadataDocuments())->toBeFalse();
});

it('builds the RFC 8414 and RFC 9728 documents from APP_URL', function (): void {
    $server = makeServer(true, true);
    config()->set('mcp-oauth.mcp_path', 'api/mcp');
    $clientAuthenticationMethods = ['none', 'client_secret_basic', 'client_secret_post'];

    expect($server->authorizationServerMetadata())->toBe([
        'issuer' => 'https://mcp-oauth.test',
        'authorization_endpoint' => 'https://mcp-oauth.test/oauth/authorize',
        'token_endpoint' => 'https://mcp-oauth.test/oauth/token',
        'registration_endpoint' => 'https://mcp-oauth.test/oauth/register',
        'scopes_supported' => ['mcp:use'],
        'response_types_supported' => ['code'],
        'grant_types_supported' => ['authorization_code', 'refresh_token'],
        'code_challenge_methods_supported' => ['S256'],
        'token_endpoint_auth_methods_supported' => $clientAuthenticationMethods,
        'authorization_response_iss_parameter_supported' => true,
        'revocation_endpoint' => 'https://mcp-oauth.test/oauth/revoke',
        'revocation_endpoint_auth_methods_supported' => $clientAuthenticationMethods,
    ])->and($server->protectedResourceMetadata())->toBe([
        'resource' => 'https://mcp-oauth.test/api/mcp',
        'authorization_servers' => ['https://mcp-oauth.test'],
        'scopes_supported' => ['mcp:use'],
        'bearer_methods_supported' => ['header'],
    ]);
});
