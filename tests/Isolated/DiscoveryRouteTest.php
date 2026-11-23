<?php

declare(strict_types=1);

use Qiick\McpOAuth\McpOAuthRoutes;
use Qiick\McpOAuth\Tests\Support\AuthorizeFlowTestCase;

uses(AuthorizeFlowTestCase::class);

/**
 * RFC 8414 and RFC 9728 documents (design §5.2 items 2–4, S13–S15; standards
 * review M1, M2, S1, S6): built from APP_URL only, honest about what is on,
 * and gone with OAuth off.
 */
const AUTHORIZATION_SERVER_METADATA = [
    'issuer' => 'https://mcp-oauth.test',
    'authorization_endpoint' => 'https://mcp-oauth.test/oauth/authorize',
    'token_endpoint' => 'https://mcp-oauth.test/oauth/token',
    'registration_endpoint' => 'https://mcp-oauth.test/oauth/register',
    'revocation_endpoint' => 'https://mcp-oauth.test/oauth/revoke',
    'scopes_supported' => ['mcp:use'],
    'response_types_supported' => ['code'],
    'grant_types_supported' => ['authorization_code', 'refresh_token'],
    'code_challenge_methods_supported' => ['S256'],
    'token_endpoint_auth_methods_supported' => ['none', 'client_secret_basic', 'client_secret_post'],
    'revocation_endpoint_auth_methods_supported' => ['none', 'client_secret_basic', 'client_secret_post'],
    'authorization_response_iss_parameter_supported' => true,
];

const PROTECTED_RESOURCE_METADATA = [
    'resource' => 'https://mcp-oauth.test/mcp',
    'authorization_servers' => ['https://mcp-oauth.test'],
    'scopes_supported' => ['mcp:use'],
    'bearer_methods_supported' => ['header'],
];

it('publishes the authorization server metadata, root and nested', function (string $path): void {
    $this->enableOAuth();
    McpOAuthRoutes::register();

    $this->getJson($path)
        ->assertOk()
        ->assertExactJson(AUTHORIZATION_SERVER_METADATA);
})->with([
    'root' => ['/.well-known/oauth-authorization-server'],
    'nested' => ['/.well-known/oauth-authorization-server/mcp'],
]);

it('publishes the protected resource metadata, root and for the MCP path', function (string $path): void {
    $this->enableOAuth();
    McpOAuthRoutes::register();

    $this->getJson($path)
        ->assertOk()
        ->assertExactJson(PROTECTED_RESOURCE_METADATA);
})->with([
    'root' => ['/.well-known/oauth-protected-resource'],
    'nested' => ['/.well-known/oauth-protected-resource/mcp'],
]);

it('follows a custom MCP path', function (): void {
    $this->enableOAuth();
    config()->set('mcp-oauth.mcp_path', 'ai/mcp');
    McpOAuthRoutes::register();

    $this->getJson('/.well-known/oauth-protected-resource/ai/mcp')
        ->assertOk()
        ->assertJsonPath('resource', 'https://mcp-oauth.test/ai/mcp');

    $this->getJson('/.well-known/oauth-protected-resource/mcp')->assertNotFound();
});

it('describes no resource other than the MCP endpoint', function (string $path): void {
    $this->enableOAuth();
    McpOAuthRoutes::register();

    $this->getJson('/.well-known/oauth-protected-resource/'.$path)->assertNotFound();
})->with(['api', 'mcp/other', 'mcpx']);

it('builds every URL from APP_URL, never from the Host header', function (): void {
    $this->enableOAuth();
    McpOAuthRoutes::register();
    $hostileServer = ['HTTP_HOST' => 'evil.example', 'HTTP_X_FORWARDED_HOST' => 'evil.example'];

    $authorizationServer = $this->getJson('/.well-known/oauth-authorization-server', $hostileServer)->json();
    $protectedResource = $this->call('GET', '/.well-known/oauth-protected-resource/mcp', server: $hostileServer)->json();

    expect(json_encode([$authorizationServer, $protectedResource]))->not->toContain('evil.example')
        ->and($authorizationServer)->toBe(AUTHORIZATION_SERVER_METADATA);
});

it('with OAuth off answers every discovery document like a missing route', function (string $path): void {
    config()->set('app.debug', false);
    config()->set('mcp-oauth.enabled', false);
    $unregisteredResponse = $this->getJson($path);

    McpOAuthRoutes::register();

    $gatedResponse = $this->getJson($path);

    expect($gatedResponse->getStatusCode())->toBe(404)
        ->and($gatedResponse->getContent())->toBe($unregisteredResponse->getContent());
})->with([
    '/.well-known/oauth-authorization-server',
    '/.well-known/oauth-authorization-server/mcp',
    '/.well-known/oauth-protected-resource',
    '/.well-known/oauth-protected-resource/mcp',
]);
