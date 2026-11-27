<?php

declare(strict_types=1);

use Illuminate\Http\Request;
use Laravel\Passport\Passport;
use Qiick\McpOAuth\AccessTokenAuthenticator;
use Qiick\McpOAuth\Data\GrantRecord;
use Qiick\McpOAuth\Data\ProtectedResourceDefinitionData;
use Qiick\McpOAuth\McpOAuthRoutes;
use Qiick\McpOAuth\McpOAuthServer;
use Qiick\McpOAuth\Models\OAuthClientMetadata;
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

it('refuses an untrusted client restricted resources or their wire scopes', function (string $registrationSource): void {
    $this->enableOAuth();
    app(McpOAuthServer::class)->registerResource(new ProtectedResourceDefinitionData(
        COMPANION_RESOURCE, 'companion:device', ['companion'],
    ));
    McpOAuthRoutes::register();
    $client = $this->createClient();
    OAuthClientMetadata::query()->where('client_id', $client->getKey())
        ->update(['registration_source' => $registrationSource]);
    $user = $this->createUser();

    $this->actingAs($user)->get($this->authorizeUrl($client).'&resource='.rawurlencode(COMPANION_RESOURCE))
        ->assertBadRequest()->assertJsonPath('error', 'invalid_target');
    $this->get($this->authorizeUrl($client, ['scope' => 'mcp:use companion:device']), ['X-Inertia' => 'true'])
        ->assertBadRequest()->assertJsonPath('error', 'invalid_scope');
})->with(['dcr', 'cimd']);

it('records the repeated resource indicators the user approved instead of any posted wire permissions', function (): void {
    $this->enableOAuth();
    app(McpOAuthServer::class)->registerResource(new ProtectedResourceDefinitionData(
        COMPANION_RESOURCE, 'companion:device', ['companion'],
    ));
    McpOAuthRoutes::register();
    $client = $this->createClient();
    OAuthClientMetadata::query()->where('client_id', $client->getKey())
        ->update(['registration_source' => 'companion']);
    $expected = [AuthorizeFlowTestCase::RESOURCE => 'mcp:use', COMPANION_RESOURCE => 'companion:device'];

    $page = $this->actingAs($this->createUser())
        ->get($this->authorizeUrl($client).'&resource='.rawurlencode(COMPANION_RESOURCE), ['X-Inertia' => 'true'])
        ->assertOk()->assertJsonPath('props.resourceScopes', $expected);

    $this->post('/oauth/authorize', [
        'auth_token' => $page->json('props.authToken'),
        'scopes' => ['mcp:read'],
        'role' => 'editor',
        'resources' => ['news'],
        'resource_scopes' => ['https://other.test/' => 'anything'],
    ])->assertRedirectContains('code=');

    expect($this->grantStore()->replacedDecisions[0]->resourceScopes)->toBe($expected);
    $grant = $this->grantStore()->activeFor((string) $client->getKey(), (string) $this->app['auth']->id());
    expect($grant?->resourceScopes)->toBe($expected);
});

it('rejects unknown, repeated and array-shaped resources before consent', function (string $additionalParameter): void {
    $this->enableOAuth();
    app(McpOAuthServer::class)->registerResource(new ProtectedResourceDefinitionData(
        COMPANION_RESOURCE, 'companion:device', ['companion'],
    ));
    McpOAuthRoutes::register();

    $this->get($this->authorizeUrl($this->createClient()).$additionalParameter)
        ->assertBadRequest()->assertJsonPath('error', 'invalid_target');
})->with([
    'unknown' => ['&resource=https%3A%2F%2Funknown.example%2Fmcp'],
    'same audience with another spelling' => ['&resource=HTTPS%3A%2F%2FMCP-OAUTH.TEST%2Fmcp%2F'],
    'array form' => ['&resource%5B%5D=https%3A%2F%2Fmcp-oauth.test%2Fmcp'],
]);

it('exchanges a one-shot code for exactly one audience and refreshes the other without retiring it', function (): void {
    $this->enableOAuth();
    app(McpOAuthServer::class)->registerResource(new ProtectedResourceDefinitionData(
        COMPANION_RESOURCE, 'companion:device', ['companion'],
    ));
    McpOAuthRoutes::register();
    $client = $this->createClient();
    OAuthClientMetadata::query()->where('client_id', $client->getKey())
        ->update(['registration_source' => 'companion']);

    $page = $this->actingAs($this->createUser())
        ->get($this->authorizeUrl($client).'&resource='.rawurlencode(COMPANION_RESOURCE), ['X-Inertia' => 'true'])
        ->assertOk();
    $approval = $this->post('/oauth/authorize', [
        'auth_token' => $page->json('props.authToken'),
        'scopes' => ['mcp:read'],
        'role' => 'editor',
        'resources' => ['news'],
    ])->assertRedirectContains('code=');
    parse_str((string) parse_url((string) $approval->headers->get('Location'), PHP_URL_QUERY), $responseParameters);
    $this->app['auth']->forgetGuards();
    $this->flushSession();

    $mcpToken = $this->post('/oauth/token', $this->codeExchange($client, $responseParameters['code']))->assertOk();
    $refreshRequest = [
        'grant_type' => 'refresh_token',
        'client_id' => (string) $client->getKey(),
        'refresh_token' => $mcpToken->json('refresh_token'),
        'resource' => COMPANION_RESOURCE,
    ];
    $companionToken = $this->post('/oauth/token', $refreshRequest)->assertOk();

    $authenticate = app(AccessTokenAuthenticator::class);
    $mcpRequest = Request::create('/mcp', server: ['HTTP_AUTHORIZATION' => 'Bearer '.$mcpToken->json('access_token')]);
    $companionRequest = Request::create('/companion', server: ['HTTP_AUTHORIZATION' => 'Bearer '.$companionToken->json('access_token')]);
    expect($authenticate->authenticate($mcpRequest))->toBeInstanceOf(GrantRecord::class)
        ->and($authenticate->authenticate($companionRequest, COMPANION_RESOURCE))->toBeInstanceOf(GrantRecord::class)
        ->and($authenticate->authenticate($mcpRequest, COMPANION_RESOURCE))->not->toBeInstanceOf(GrantRecord::class)
        ->and($authenticate->authenticate($companionRequest))->not->toBeInstanceOf(GrantRecord::class);
    expect(Passport::token()->newQuery()->where('audience', COMPANION_RESOURCE)->sole()->scopes)->toBe(['companion:device'])
        ->and(Passport::token()->newQuery()->where('audience', AuthorizeFlowTestCase::RESOURCE)->sole()->scopes)->toBe(['mcp:use']);

    $this->post('/oauth/token', $refreshRequest)->assertBadRequest()->assertJsonPath('error', 'invalid_grant');
    expect($authenticate->authenticate($mcpRequest))->not->toBeInstanceOf(GrantRecord::class)
        ->and($authenticate->authenticate($companionRequest, COMPANION_RESOURCE))->not->toBeInstanceOf(GrantRecord::class);
});
