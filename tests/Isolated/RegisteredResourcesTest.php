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
        ))->toThrow(InvalidArgumentException::class)
        ->and(fn () => $server->registerResource(
            new ProtectedResourceDefinitionData($server->issuer().'/another', 'companion:device', ['companion']),
        ))->toThrow(InvalidArgumentException::class)
        ->and(fn () => $server->registerResource(
            new ProtectedResourceDefinitionData($server->issuer().'/another', 'mcp:use', ['companion']),
        ))->toThrow(InvalidArgumentException::class);
});

it('requires the registered resource to use a canonical child path under the issuer', function (string $identifier): void {
    expect(fn () => app(McpOAuthServer::class)->registerResource(new ProtectedResourceDefinitionData(
        $identifier, 'companion:device', ['companion'],
    )))->toThrow(InvalidArgumentException::class);
})->with([
    'other issuer' => ['https://other.example/companion'],
    'dot segment' => ['https://mcp-oauth.test/other/../companion'],
    'overlong path' => ['https://mcp-oauth.test/'.str_repeat('a', 512)],
]);

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
    $this->get($this->authorizeUrl($client, ['scope' => 'companion:device']).'&scope=mcp%3Ause', ['X-Inertia' => 'true'])
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

    $authorizationUrl = $this->authorizeUrl($client).'&resource='.rawurlencode(COMPANION_RESOURCE);
    $page = $this->actingAs($this->createUser())
        ->get($authorizationUrl, ['X-Inertia' => 'true'])
        ->assertOk()->assertJsonPath('props.resourceScopes', $expected)
        ->assertJsonPath('url', $authorizationUrl)
        ->assertJsonFragment(['label' => 'Resource', 'value' => implode(', ', array_keys($expected))]);

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
    'PHP field alias' => ['&resource%00=https%3A%2F%2Fmcp-oauth.test%2Fmcp'],
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

    expect($authenticate->authenticate($companionRequest, 'https://unknown.example'))->not->toBeInstanceOf(GrantRecord::class);
    $metadata = OAuthClientMetadata::query()->where('client_id', $client->getKey())->sole();
    $metadata->update(['registration_source' => 'dcr']);
    expect($authenticate->authenticate($companionRequest, COMPANION_RESOURCE))->not->toBeInstanceOf(GrantRecord::class);
    $metadata->update(['registration_source' => 'companion']);

    // A corrupted audience column cannot turn a signed MCP scope into a Companion credential.
    $mcpRow = Passport::token()->newQuery()->where('audience', AuthorizeFlowTestCase::RESOURCE)->sole();
    $mcpRow->forceFill(['audience' => COMPANION_RESOURCE])->save();
    expect($authenticate->authenticate($mcpRequest, COMPANION_RESOURCE))->not->toBeInstanceOf(GrantRecord::class);
    $mcpRow->forceFill(['audience' => AuthorizeFlowTestCase::RESOURCE])->save();

    $this->post('/oauth/token', $refreshRequest)->assertBadRequest()->assertJsonPath('error', 'invalid_grant');
    expect($authenticate->authenticate($mcpRequest))->not->toBeInstanceOf(GrantRecord::class)
        ->and($authenticate->authenticate($companionRequest, COMPANION_RESOURCE))->not->toBeInstanceOf(GrantRecord::class);
});

it('cannot refresh into another resource unless the user approved the corresponding pair', function (): void {
    $this->enableOAuth();
    app(McpOAuthServer::class)->registerResource(new ProtectedResourceDefinitionData(
        COMPANION_RESOURCE, 'companion:device', ['companion'],
    ));
    McpOAuthRoutes::register();
    $client = $this->createClient();
    OAuthClientMetadata::query()->where('client_id', $client->getKey())
        ->update(['registration_source' => 'companion']);
    ['code' => $code] = $this->obtainAuthorizationCode($client);
    $tokens = $this->post('/oauth/token', $this->codeExchange($client, $code))->assertOk();
    $refresh = [
        'grant_type' => 'refresh_token',
        'client_id' => $client->getKey(),
        'refresh_token' => $tokens->json('refresh_token'),
        'resource' => COMPANION_RESOURCE,
    ];

    $this->post('/oauth/token', $refresh)->assertBadRequest()->assertJsonPath('error', 'invalid_target');
    $this->post('/oauth/token', [...$refresh, 'resource' => AuthorizeFlowTestCase::RESOURCE])
        ->assertOk()->assertJsonPath('scope', 'mcp:use');
});
