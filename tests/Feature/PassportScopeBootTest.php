<?php

declare(strict_types=1);

use Laravel\Passport\Bridge\ScopeRepository;
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
    expect(Passport::defaultScopes())->toBe([McpOAuthServer::WIRE_SCOPE])
        ->and(Passport::scopes()->pluck('id')->all())->toBe([McpOAuthServer::WIRE_SCOPE]);
});

it('returns null for unknown scopes so league rejects invalid_scope', function (): void {
    /** @var ScopeRepository $scopeRepository */
    $scopeRepository = $this->app->make(ScopeRepository::class);

    expect($scopeRepository->getScopeEntityByIdentifier('nope'))->toBeNull()
        ->and($scopeRepository->getScopeEntityByIdentifier(McpOAuthServer::WIRE_SCOPE))->not->toBeNull();
});
