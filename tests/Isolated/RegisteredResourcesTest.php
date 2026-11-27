<?php

declare(strict_types=1);

use Qiick\McpOAuth\Data\ProtectedResourceDefinitionData;
use Qiick\McpOAuth\McpOAuthRoutes;
use Qiick\McpOAuth\McpOAuthServer;
use Qiick\McpOAuth\Tests\Support\AuthorizeFlowTestCase;

uses(AuthorizeFlowTestCase::class);

const COMPANION_RESOURCE = 'https://mcp-oauth.test/companion';

it('advertises the wire scope and protected resource metadata of a registered audience', function (): void {
    $this->enableOAuth();
    app(McpOAuthServer::class)->registerResource(new ProtectedResourceDefinitionData(
        identifier: COMPANION_RESOURCE,
        scope: 'companion:device',
        allowedClientClasses: ['companion'],
    ));
    McpOAuthRoutes::register();

    $this->get('/.well-known/oauth-authorization-server')
        ->assertOk()
        ->assertJsonPath('scopes_supported', ['mcp:use', 'companion:device']);
    $this->get('/.well-known/oauth-protected-resource/companion')
        ->assertOk()
        ->assertExactJson([
            'resource' => COMPANION_RESOURCE,
            'authorization_servers' => ['https://mcp-oauth.test'],
            'scopes_supported' => ['companion:device'],
            'bearer_methods_supported' => ['header'],
        ]);
    $this->get('/.well-known/oauth-protected-resource/mcp')
        ->assertOk()
        ->assertJsonPath('scopes_supported', ['mcp:use']);
});

it('refuses a resource registration that shadows the MCP audience or another resource', function (): void {
    $server = app(McpOAuthServer::class);
    $companion = new ProtectedResourceDefinitionData(COMPANION_RESOURCE, 'companion:device', ['companion']);
    $server->registerResource($companion);

    expect(fn () => $server->registerResource($companion))->toThrow(InvalidArgumentException::class)
        ->and(fn () => $server->registerResource(
            new ProtectedResourceDefinitionData($server->resourceIdentifier(), 'companion:device', ['companion']),
        ))->toThrow(InvalidArgumentException::class);
});
