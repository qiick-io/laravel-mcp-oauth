<?php

declare(strict_types=1);

use Laravel\Passport\Passport;
use Qiick\McpOAuth\McpOAuthServer;

/**
 * Design §5.6: tokensCan and defaultScopes come from McpOAuthServer.
 */
it('registers mcp:use via tokensCan from McpOAuthServer scope descriptions', function (): void {
    expect(Passport::hasScope(McpOAuthServer::WIRE_SCOPE))->toBeTrue()
        ->and(Passport::scopesFor([McpOAuthServer::WIRE_SCOPE]))->toHaveCount(1)
        ->and(Passport::scopesFor([McpOAuthServer::WIRE_SCOPE])[0]->id)->toBe(McpOAuthServer::WIRE_SCOPE)
        ->and(Passport::scopesFor([McpOAuthServer::WIRE_SCOPE])[0]->description)
        ->toBe('Use the MCP server with the access the user grants');
});

it('sets mcp:use as the only default Passport scope', function (): void {
    expect(Passport::defaultScopes())->toBe([McpOAuthServer::WIRE_SCOPE]);
});
