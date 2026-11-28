<?php

declare(strict_types=1);

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Str;
use Laravel\Passport\Passport;
use Qiick\McpOAuth\AccessTokenAuthenticator;
use Qiick\McpOAuth\Contracts\GrantStore;
use Qiick\McpOAuth\Data\GrantRecord;
use Qiick\McpOAuth\Data\ProtectedResourceDefinitionData;
use Qiick\McpOAuth\Events\McpConsentApprovedEvent;
use Qiick\McpOAuth\Http\Middleware\ValidateAuthorizationRequestMiddleware;
use Qiick\McpOAuth\McpOAuthRoutes;
use Qiick\McpOAuth\McpOAuthServer;
use Qiick\McpOAuth\Models\OAuthClientMetadata;
use Qiick\McpOAuth\Models\OAuthConsentRecord;
use Qiick\McpOAuth\Tests\Support\AuthorizeFlowTestCase;

uses(AuthorizeFlowTestCase::class);

const COMPANION_RESOURCE = 'https://mcp-oauth.test/companion';
const COMPANION_RESOURCE_NORMALIZABLE = 'HTTPS://MCP-OAUTH.TEST/companion/';

function registerCompanionResource(): void
{
    app(McpOAuthServer::class)->registerResource(new ProtectedResourceDefinitionData(
        COMPANION_RESOURCE, 'companion:device', ['companion'],
    ));
}

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

    expect(McpOAuthRoutes::servingProblems())->toBe([]);
    Route::get('/.well-known/oauth-protected-resource/companion', static fn (): string => 'foreign metadata');
    expect(McpOAuthRoutes::servingProblems())->toBe([
        'GET https://mcp-oauth.test/.well-known/oauth-protected-resource/companion is served by another handler',
    ]);
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
    registerCompanionResource();
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

it('retains the repeated resource indicators across the guest login redirect', function (): void {
    $this->enableOAuth();
    registerCompanionResource();
    McpOAuthRoutes::register();
    $client = $this->createClient();
    OAuthClientMetadata::query()->where('client_id', $client->getKey())->update(['registration_source' => 'companion']);
    $authorizationUrl = $this->authorizeUrl($client).'&resource='.rawurlencode(COMPANION_RESOURCE_NORMALIZABLE);

    $this->get($authorizationUrl)->assertRedirect(route('login'))
        ->assertSessionHas('url.intended', app(McpOAuthServer::class)->issuer().$authorizationUrl);
});

it('records the repeated resource indicators the user approved instead of any posted wire permissions', function (): void {
    Event::fake([McpConsentApprovedEvent::class]);
    $this->enableOAuth();
    registerCompanionResource();
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
    expect($grant?->resourceScopes)->toBe($expected)
        ->and(OAuthConsentRecord::query()->sole()->getAttribute('resource_scopes'))->toEqual($expected);
    Event::assertDispatched(McpConsentApprovedEvent::class, fn (McpConsentApprovedEvent $event): bool => $event->resourceScopes === $expected);
});

it('retains each displayed resource when the user denies consent', function (): void {
    $this->enableOAuth();
    registerCompanionResource();
    McpOAuthRoutes::register();
    $client = $this->createClient();
    OAuthClientMetadata::query()->where('client_id', $client->getKey())->update(['registration_source' => 'companion']);
    $authorizationUrl = $this->authorizeUrl($client, ['resource' => COMPANION_RESOURCE])
        .'&resource='.rawurlencode(AuthorizeFlowTestCase::RESOURCE);
    $page = $this->actingAs($this->createUser())
        ->get($authorizationUrl, ['X-Inertia' => 'true'])
        ->assertOk();
    $this->delete('/oauth/authorize', ['auth_token' => $page->json('props.authToken')])
        ->assertRedirectContains('error=access_denied');

    $evidence = OAuthConsentRecord::query()->sole();
    expect($evidence->getAttribute('decision'))->toBe('denied')
        ->and($evidence->getAttribute('resource'))->toBe(COMPANION_RESOURCE)
        ->and($evidence->getAttribute('resource_scopes'))->toEqual([
            AuthorizeFlowTestCase::RESOURCE => 'mcp:use', COMPANION_RESOURCE => 'companion:device',
        ]);
});

it('refuses a pending approval when the client class can no longer obtain one of its resources', function (): void {
    $this->enableOAuth();
    registerCompanionResource();
    McpOAuthRoutes::register();
    $client = $this->createClient();
    $metadata = OAuthClientMetadata::query()->where('client_id', $client->getKey())->sole();
    $metadata->update(['registration_source' => 'companion']);
    $page = $this->actingAs($this->createUser())
        ->get($this->authorizeUrl($client).'&resource='.rawurlencode(COMPANION_RESOURCE), ['X-Inertia' => 'true'])
        ->assertOk();
    $metadata->update(['registration_source' => 'dcr']);

    $this->post('/oauth/authorize', [
        'auth_token' => $page->json('props.authToken'),
        'scopes' => ['mcp:read'],
        'role' => 'editor',
        'resources' => ['news'],
    ])->assertForbidden()->assertHeaderMissing('Location');
    expect($this->grantStore()->replacedDecisions)->toBeEmpty();
});

it('rejects unknown, repeated and array-shaped resources before consent', function (string $additionalParameter): void {
    $this->enableOAuth();
    registerCompanionResource();
    McpOAuthRoutes::register();

    $client = $this->createClient();
    OAuthClientMetadata::query()->where('client_id', $client->getKey())->update(['registration_source' => 'companion']);
    $this->get($this->authorizeUrl($client).$additionalParameter)
        ->assertBadRequest()->assertJsonPath('error', 'invalid_target');
})->with([
    'unknown' => ['&resource=https%3A%2F%2Funknown.example%2Fmcp'],
    'same audience with another spelling' => ['&resource=HTTPS%3A%2F%2FMCP-OAUTH.TEST%2Fmcp%2F'],
    'array form' => ['&resource%5B%5D=https%3A%2F%2Fmcp-oauth.test%2Fmcp'],
    'PHP field alias' => ['&resource%00=https%3A%2F%2Fmcp-oauth.test%2Fmcp'],
    'changed path case' => ['&resource='.rawurlencode('https://mcp-oauth.test/Companion')],
    'two trailing slashes' => ['&resource='.rawurlencode(COMPANION_RESOURCE.'//')],
    'same additional resource with another spelling' => [
        '&resource='.rawurlencode(COMPANION_RESOURCE).'&resource='.rawurlencode(COMPANION_RESOURCE_NORMALIZABLE),
    ],
]);

it('exchanges a one-shot code for exactly one audience and refreshes the other without retiring it', function (): void {
    $this->enableOAuth();
    registerCompanionResource();
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
    $boundGrant = $this->grantStore()->find(Passport::token()->newQuery()->sole()->api_key_id);
    expect($boundGrant)->toBeInstanceOf(GrantRecord::class);
    $this->grantStore()->seed(new GrantRecord(
        (string) Str::uuid7(), $boundGrant->clientId, $boundGrant->userIdentifier, false,
        $boundGrant->scopes, $boundGrant->authorizedAt, null, resourceScopes: $boundGrant->resourceScopes,
    ));

    $refreshRequest = [
        'grant_type' => 'refresh_token',
        'client_id' => (string) $client->getKey(),
        'refresh_token' => $mcpToken->json('refresh_token'),
        'resource' => COMPANION_RESOURCE_NORMALIZABLE,
    ];
    $companionToken = $this->post('/oauth/token', $refreshRequest)->assertOk();
    expect(Passport::token()->newQuery()->where('audience', COMPANION_RESOURCE)->sole()->api_key_id)->toBe($boundGrant->id);

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
    registerCompanionResource();
    McpOAuthRoutes::register();
    $client = $this->createClient();
    OAuthClientMetadata::query()->where('client_id', $client->getKey())
        ->update(['registration_source' => 'companion']);
    ['code' => $code] = $this->obtainAuthorizationCode($client);
    $this->post('/oauth/token', $this->codeExchange($client, $code, ['resource' => 'https://unknown.example']))
        ->assertBadRequest()->assertJsonPath('error', 'invalid_target');
    $this->post('/oauth/token', $this->codeExchange($client, $code, ['scope' => 'companion:device']))
        ->assertBadRequest()->assertJsonPath('error', 'invalid_scope');
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

it('requires the registered audience, exact approved pair and live bound grant at bearer use', function (): void {
    $this->enableOAuth();
    registerCompanionResource();
    McpOAuthRoutes::register();
    $client = $this->createClient();
    ['code' => $code] = $this->obtainAuthorizationCode($client);
    $tokens = $this->post('/oauth/token', $this->codeExchange($client, $code))->assertOk();
    $bearer = Request::create('/mcp', server: ['HTTP_AUTHORIZATION' => 'Bearer '.$tokens->json('access_token')]);
    $authenticate = app(AccessTokenAuthenticator::class);
    $grant = $authenticate->authenticate($bearer);
    expect($grant)->toBeInstanceOf(GrantRecord::class);

    $token = Passport::token()->newQuery()->sole();
    $token->forceFill(['api_key_id' => (string) Str::uuid7()])->save();
    expect($authenticate->authenticate($bearer))->not->toBeInstanceOf(GrantRecord::class);
    $token->forceFill(['api_key_id' => $grant->id])->save();

    foreach ([
        ['clientId' => $grant->clientId, 'userIdentifier' => $grant->userIdentifier, 'revoked' => true, 'resourceScopes' => $grant->resourceScopes],
        ['clientId' => (string) $this->createClient()->getKey(), 'userIdentifier' => $grant->userIdentifier, 'revoked' => false, 'resourceScopes' => $grant->resourceScopes],
        ['clientId' => $grant->clientId, 'userIdentifier' => 'another-principal', 'revoked' => false, 'resourceScopes' => $grant->resourceScopes],
        ['clientId' => $grant->clientId, 'userIdentifier' => $grant->userIdentifier, 'revoked' => false, 'resourceScopes' => [COMPANION_RESOURCE => 'companion:device']],
    ] as $inconsistentGrant) {
        $this->grantStore()->seed(new GrantRecord(
            id: $grant->id,
            clientId: $inconsistentGrant['clientId'],
            userIdentifier: $inconsistentGrant['userIdentifier'],
            revoked: $inconsistentGrant['revoked'],
            scopes: $grant->scopes,
            authorizedAt: $grant->authorizedAt,
            lastUsedAt: null,
            resourceScopes: $inconsistentGrant['resourceScopes'],
        ));
        expect($authenticate->authenticate($bearer))->not->toBeInstanceOf(GrantRecord::class);
    }

    $this->grantStore()->seed(new GrantRecord(
        $grant->id, $grant->clientId, $grant->userIdentifier, false, $grant->scopes, $grant->authorizedAt, null,
    ));
    $unknownResource = 'https://mcp-oauth.test/unregistered';
    $token->forceFill(['audience' => $unknownResource])->save();
    expect($authenticate->authenticate($bearer, $unknownResource))->not->toBeInstanceOf(GrantRecord::class);
});

it('sets the selected scopes on a synthesized authorize request and keeps an unrelated login destination', function (): void {
    $this->enableOAuth();
    registerCompanionResource();
    $client = $this->createClient();
    OAuthClientMetadata::query()->where('client_id', $client->getKey())->update(['registration_source' => 'companion']);
    $middleware = app(ValidateAuthorizationRequestMiddleware::class);
    $authorizationUrl = $this->authorizeUrl($client, ['resource' => COMPANION_RESOURCE, 'scope' => null]);
    $request = Request::create($authorizationUrl);
    $request->server->remove('QUERY_STRING');
    $response = $middleware->handle($request, static fn (Request $accepted) => response()->json($accepted->query()));
    expect($response->getStatusCode())->toBe(200)
        ->and(json_decode((string) $response->getContent(), true)['scope'])->toBe('companion:device');

    $request->query->set('scope', McpOAuthServer::WIRE_SCOPE);
    expect($middleware->handle($request, static fn () => response('unexpected'))->getStatusCode())->toBe(400);

    $request = Request::create($authorizationUrl);
    $session = app('session')->driver();
    $session->put('url.intended', '/somewhere-else');
    $request->setLaravelSession($session);
    $middleware->handle($request, static fn () => redirect('/login'));
    expect($session->get('url.intended'))->toBe('/somewhere-else');
});

it('rejects duplicate or ambiguous scope fields and keeps the legacy MCP-only consent shape', function (): void {
    $this->enableOAuth();
    registerCompanionResource();
    McpOAuthRoutes::register();
    $client = $this->createClient();
    $this->actingAs($this->createUser());

    foreach (['&scope=companion%3Adevice', '&scope%5B%5D=mcp%3Ause'] as $ambiguousScope) {
        $this->get($this->authorizeUrl($client).$ambiguousScope)
            ->assertBadRequest()->assertJsonPath('error', 'invalid_scope');
    }

    $this->get($this->authorizeUrl($client), ['X-Inertia' => 'true'])
        ->assertOk()->assertJsonMissingPath('props.resourceScopes');
});

it('refuses to record approval when the product discards an approved resource', function (): void {
    Event::fake([McpConsentApprovedEvent::class]);
    $this->enableOAuth();
    registerCompanionResource();
    McpOAuthRoutes::register();
    $client = $this->createClient();
    OAuthClientMetadata::query()->where('client_id', $client->getKey())->update(['registration_source' => 'companion']);
    $user = $this->createUser();
    $grant = new GrantRecord(
        (string) Str::uuid7(), (string) $client->getKey(), (string) $user->getAuthIdentifier(), false, ['mcp:read'], null, null,
    );
    $this->mock(GrantStore::class)->shouldReceive('replace')->once()->andReturn($grant);

    $page = $this->actingAs($user)
        ->get($this->authorizeUrl($client).'&resource='.rawurlencode(COMPANION_RESOURCE), ['X-Inertia' => 'true'])
        ->assertOk();
    $this->withoutExceptionHandling();
    expect(fn () => $this->post('/oauth/authorize', [
        'auth_token' => $page->json('props.authToken'),
        'scopes' => ['mcp:read'],
        'role' => 'editor',
        'resources' => ['news'],
    ]))->toThrow(LogicException::class, 'The GrantStore must preserve the approved resource scopes.');
    expect(OAuthConsentRecord::query()->exists())->toBeFalse();
    Event::assertNotDispatched(McpConsentApprovedEvent::class);
});
