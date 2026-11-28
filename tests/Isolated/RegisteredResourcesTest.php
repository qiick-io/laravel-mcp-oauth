<?php

declare(strict_types=1);

use Defuse\Crypto\Crypto;
use GuzzleHttp\Psr7\Response as PsrResponse;
use GuzzleHttp\Psr7\ServerRequest;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Str;
use Laravel\Passport\Bridge\ClientRepository as PassportClientRepository;
use Laravel\Passport\Bridge\Scope;
use Laravel\Passport\Passport;
use League\OAuth2\Server\AuthorizationServer;
use League\OAuth2\Server\Exception\OAuthServerException;
use Qiick\McpOAuth\AccessTokenAuthenticator;
use Qiick\McpOAuth\Bridge\ResourceAccessTokenRepository;
use Qiick\McpOAuth\Bridge\ResourceScopeRepository;
use Qiick\McpOAuth\Contracts\GrantStore;
use Qiick\McpOAuth\Data\GrantRecord;
use Qiick\McpOAuth\Data\ProtectedResourceDefinitionData;
use Qiick\McpOAuth\Data\RevocationReason;
use Qiick\McpOAuth\Data\TokenResourceSelectionData;
use Qiick\McpOAuth\Events\McpConsentApprovedEvent;
use Qiick\McpOAuth\Http\Controllers\ProtectedResourceMetadataController;
use Qiick\McpOAuth\Http\Middleware\ValidateAuthorizationRequestMiddleware;
use Qiick\McpOAuth\McpOAuthRoutes;
use Qiick\McpOAuth\McpOAuthServer;
use Qiick\McpOAuth\Models\OAuthAuthCodeExchange;
use Qiick\McpOAuth\Models\OAuthClientMetadata;
use Qiick\McpOAuth\Models\OAuthConsentRecord;
use Qiick\McpOAuth\Services\ResourceIndicatorsService;
use Qiick\McpOAuth\Tests\Support\AuthorizeFlowTestCase;
use Qiick\McpOAuth\Tests\Support\HookedGrantStore;

uses(AuthorizeFlowTestCase::class);

const COMPANION_RESOURCE = 'https://mcp-oauth.test/companion';
const COMPANION_RESOURCE_NORMALIZABLE = 'HTTPS://MCP-OAUTH.TEST/companion/';

it('returns 404 for a metadata route cached for a removed resource', function (): void {
    Route::get('/.well-known/oauth-protected-resource/retired-resource', ProtectedResourceMetadataController::class)
        ->defaults('resourceIdentifier', 'https://mcp-oauth.test/retired-resource');

    $this->getJson('/.well-known/oauth-protected-resource/retired-resource')->assertNotFound();
});

function registerCompanionResource(): void
{
    app(McpOAuthServer::class)->registerResource(new ProtectedResourceDefinitionData(
        COMPANION_RESOURCE, 'companion:device', ['companion'],
    ));
}

it('accepts an OAuth scope of exactly 255 bytes and a list of client classes', function (): void {
    $scope = str_repeat('s', 255);
    $definition = new ProtectedResourceDefinitionData(COMPANION_RESOURCE, $scope, ['companion', 'registered_local']);

    expect($definition->scope)->toBe($scope)
        ->and($definition->allowedClientClasses)->toBe(['companion', 'registered_local']);
});

it('refuses a scope that does not fit a single bounded OAuth token', function (string $scope): void {
    expect(fn () => new ProtectedResourceDefinitionData(COMPANION_RESOURCE, $scope, ['companion']))
        ->toThrow(InvalidArgumentException::class, 'one OAuth scope');
})->with([
    'empty' => [''],
    'space-separated scopes' => ['companion:device mcp:use'],
    'quotation mark' => ['"companion:device"'],
    'scope over the storage limit' => [str_repeat('s', 256)],
]);

it('refuses malformed client class lists', function (array $clientClasses, string $message): void {
    expect(fn () => new ProtectedResourceDefinitionData(COMPANION_RESOURCE, 'companion:device', $clientClasses))
        ->toThrow(InvalidArgumentException::class, $message);
})->with([
    'empty list' => [[], 'one or more allowed client classes'],
    'associative array' => [['trusted' => 'companion'], 'one or more allowed client classes'],
    'non-string class' => [[true], 'must be a registration class'],
    'non-canonical class' => [['Companion'], 'must be a registration class'],
    'class longer than 16 characters' => [['registered_client'], 'must be a registration class'],
]);

it('reads literal protocol fields without using PHP parameter coercion', function (string $encoded, mixed $parsedValue, string $field, ?array $expected): void {
    expect(app(ResourceIndicatorsService::class)->parse($encoded, $parsedValue, $field))->toBe($expected);
})->with([
    'absent synthesized field' => ['', null, 'resource', []],
    'synthesized scalar' => ['', COMPANION_RESOURCE, 'resource', [COMPANION_RESOURCE]],
    'synthesized array' => ['', [COMPANION_RESOURCE], 'resource', null],
    'literal empty field' => ['resource', COMPANION_RESOURCE, 'resource', ['']],
    'wire order and embedded equals' => ['resource=https%3A%2F%2Fa.example%2Fone%3Fmode=yes&resource=https%3A%2F%2Fa.example%2Ftwo', null, 'resource', ['https://a.example/one?mode=yes', 'https://a.example/two']],
    'unrelated field' => ['resource_scope=companion&state=opaque', COMPANION_RESOURCE, 'resource', []],
    'leading space' => ['%20resource=one', 'one', 'resource', null],
    'NUL suffix' => ['resource%00alias=one', 'one', 'resource', null],
    'bracket field' => ['resource%5B0%5D=one', ['one'], 'resource', null],
    'scope is a distinct field' => ['resource=one&scope=mcp%3Ause+companion%3Adevice', null, 'scope', ['mcp:use companion:device']],
]);

it('limits legacy scope compatibility to the MCP audience', function (): void {
    $service = app(ResourceIndicatorsService::class);
    $mcpResource = app(McpOAuthServer::class)->resourceIdentifier();
    $legacyGrant = new GrantRecord('grant', 'client', 'user', false, [], null, null);
    $companionGrant = new GrantRecord('companion-grant', 'client', 'user', false, [], null, null, resourceScopes: [COMPANION_RESOURCE => 'companion:device']);

    expect($service->allowsRequestedScope('mcp:use unadvertised', [$mcpResource => 'mcp:use']))->toBeTrue()
        ->and($service->allowsRequestedScope('companion:device unadvertised', $companionGrant->resourceScopes))->toBeFalse()
        ->and($service->scopeInGrant($legacyGrant, $mcpResource))->toBe('mcp:use')
        ->and($service->scopeInGrant($legacyGrant, COMPANION_RESOURCE))->toBeNull()
        ->and($service->scopeInGrant($companionGrant, $mcpResource))->toBeNull();
});

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
    request()->attributes->set(TokenResourceSelectionData::REQUEST_ATTRIBUTE, new TokenResourceSelectionData(
        COMPANION_RESOURCE, 'companion:device',
    ));
    $request = (new ServerRequest('POST', '/oauth/token'))->withParsedBody($refresh);
    expect(fn () => app(AuthorizationServer::class)->respondToAccessTokenRequest($request, new PsrResponse))
        ->toThrow(function (OAuthServerException $exception): void {
            expect($exception->getErrorType())->toBe('invalid_target')
                ->and($exception->getCode())->toBe(0);
        });

    $this->post('/oauth/token', [...$refresh, 'resource' => AuthorizeFlowTestCase::RESOURCE])
        ->assertOk()->assertJsonPath('scope', 'mcp:use');
});

it('refreshes a legacy credential with a numeric principal in the encrypted payload', function (): void {
    $this->enableOAuth();
    registerCompanionResource();
    McpOAuthRoutes::register();
    $client = $this->createClient();
    ['code' => $code, 'user' => $user] = $this->obtainAuthorizationCode($client);
    $tokens = $this->post('/oauth/token', $this->codeExchange($client, $code))->assertOk();
    $encryptionKey = Passport::tokenEncryptionKey(app('encrypter'));
    $payload = json_decode(Crypto::decryptWithPassword($tokens->json('refresh_token'), $encryptionKey), true, flags: JSON_THROW_ON_ERROR);
    $payload['user_id'] = (int) $user->getAuthIdentifier();

    $this->post('/oauth/token', [
        'grant_type' => 'refresh_token',
        'client_id' => $client->getKey(),
        'refresh_token' => Crypto::encryptWithPassword(json_encode($payload, JSON_THROW_ON_ERROR), $encryptionKey),
        'resource' => AuthorizeFlowTestCase::RESOURCE,
    ])->assertOk()->assertJsonPath('scope', 'mcp:use');
    expect(Passport::token()->newQuery()->where('revoked', false)->sole()->user_id)->toEqual($user->getAuthIdentifier());
});

it('refuses refresh before rotating credentials when its grant context changed after validation', function (string $change): void {
    $this->enableOAuth();
    registerCompanionResource();
    $store = new HookedGrantStore($this->grantStore());
    app()->instance(GrantStore::class, $store);
    McpOAuthRoutes::register();
    $client = $this->createClient();
    ['code' => $code] = $this->obtainAuthorizationCode($client);
    $tokens = $this->post('/oauth/token', $this->codeExchange($client, $code))->assertOk();
    $accessToken = Passport::token()->newQuery()->sole();
    $grant = $store->find($accessToken->getAttribute('api_key_id'));
    $store->afterNextFind = static function () use ($change, $store, $grant, $accessToken): void {
        match ($change) {
            'access token gone' => $accessToken->delete(),
            'grant gone' => $store->isGrantGone = true,
            'revoked' => $store->grantStore->revoke($grant->id, null, RevocationReason::User),
            default => $store->grantStore->seed(new GrantRecord(
                $grant->id,
                $change === 'client' ? (string) Str::uuid7() : $grant->clientId,
                $change === 'principal' ? 'another-user' : $grant->userIdentifier,
                false, $grant->scopes, $grant->authorizedAt, null,
                resourceScopes: $grant->resourceScopes,
            )),
        };
    };

    $this->post('/oauth/token', [
        'grant_type' => 'refresh_token',
        'client_id' => $client->getKey(),
        'refresh_token' => $tokens->json('refresh_token'),
        'resource' => AuthorizeFlowTestCase::RESOURCE,
    ])->assertBadRequest()->assertJsonPath('error', 'invalid_grant');
    expect(Passport::refreshToken()->newQuery()->sole()->getAttribute('revoked'))->toBeFalse();
})->with(['access token gone', 'grant gone', 'revoked', 'client', 'principal']);

it('refreshes an approved resource bound through an integer product key', function (): void {
    $this->enableOAuth();
    registerCompanionResource();
    McpOAuthRoutes::register();
    $client = $this->createClient();
    ['code' => $code] = $this->obtainAuthorizationCode($client);
    $tokens = $this->post('/oauth/token', $this->codeExchange($client, $code))->assertOk();
    $accessToken = Passport::token()->newQuery()->sole();
    $grantStore = $this->grantStore();
    $grant = $grantStore->find($accessToken->getAttribute('api_key_id'));
    $grantStore->seed(new GrantRecord(
        '7', $grant->clientId, $grant->userIdentifier, false,
        $grant->scopes, $grant->authorizedAt, null, resourceScopes: $grant->resourceScopes,
    ));
    Schema::table('oauth_access_tokens', static function (Blueprint $table): void {
        $table->unsignedBigInteger('grant_number')->nullable();
    });
    config()->set('mcp-oauth.grant_binding_column', 'grant_number');
    $accessToken->forceFill(['grant_number' => 7])->save();

    $this->post('/oauth/token', [
        'grant_type' => 'refresh_token',
        'client_id' => $client->getKey(),
        'refresh_token' => $tokens->json('refresh_token'),
        'resource' => AuthorizeFlowTestCase::RESOURCE,
    ])->assertOk()->assertJsonPath('scope', 'mcp:use');
    expect(Passport::token()->newQuery()->where('revoked', false)->sole()->getAttribute('grant_number'))->toBe(7);
});

it('preserves League refresh handling when resource selection is absent', function (): void {
    $this->enableOAuth();
    registerCompanionResource();
    McpOAuthRoutes::register();
    $client = $this->createClient();
    ['code' => $code] = $this->obtainAuthorizationCode($client);
    $tokens = $this->post('/oauth/token', $this->codeExchange($client, $code))->assertOk();
    $source = Passport::token()->newQuery()->sole();
    request()->attributes->remove(TokenResourceSelectionData::REQUEST_ATTRIBUTE);

    $refresh = (new ServerRequest('POST', '/oauth/token'))->withParsedBody([
        'grant_type' => 'refresh_token',
        'client_id' => $client->getKey(),
        'refresh_token' => $tokens->json('refresh_token'),
    ]);
    $response = app(AuthorizationServer::class)->respondToAccessTokenRequest($refresh, new PsrResponse);

    expect($response->getStatusCode())->toBe(200)
        ->and($source->refresh()->revoked)->toBeTrue();
});

it('fails a selected-audience refresh if the source token or its binding disappears', function (bool $shouldDeleteToken): void {
    $this->enableOAuth();
    registerCompanionResource();
    McpOAuthRoutes::register();
    $client = $this->createClient();
    ['code' => $code] = $this->obtainAuthorizationCode($client);
    $this->post('/oauth/token', $this->codeExchange($client, $code))->assertOk();
    $token = Passport::token()->newQuery()->sole();

    request()->attributes->set(TokenResourceSelectionData::REQUEST_ATTRIBUTE, new TokenResourceSelectionData(
        AuthorizeFlowTestCase::RESOURCE, 'mcp:use', $token->getAttribute('api_key_id'),
    ));

    if ($shouldDeleteToken) {
        $token->delete();
    } else {
        $token->forceFill(['api_key_id' => null])->save();
    }

    expect(fn () => app(ResourceAccessTokenRepository::class)->revokeAccessToken($token->getKey()))
        ->toThrow(OAuthServerException::class, 'The refresh token is invalid.');
})->with(['token deleted' => [true], 'binding cleared' => [false]]);

it('preserves the revoked legacy exchange behavior when the product registers another resource', function (): void {
    $this->enableOAuth();
    registerCompanionResource();
    McpOAuthRoutes::register();
    $client = $this->createClient();
    ['code' => $code, 'user' => $user] = $this->obtainAuthorizationCode($client);
    $grant = $this->grantStore()->activeFor((string) $client->getKey(), (string) $user->getKey());
    $this->grantStore()->revoke($grant->id, null, RevocationReason::User);

    $this->post('/oauth/token', $this->codeExchange($client, $code))->assertOk();

    $token = Passport::token()->newQuery()->sole();
    expect($token->revoked)->toBeTrue()
        ->and($token->getAttribute('api_key_id'))->toBeNull()
        ->and($token->getAttribute('audience'))->toBeNull();
});

it('limits the code exchange in Passport to the approved audience and its grant', function (string $state): void {
    $this->enableOAuth();
    registerCompanionResource();
    McpOAuthRoutes::register();
    $client = $this->createClient();
    $clientId = (string) $client->getKey();
    $clientEntity = app(PassportClientRepository::class)->getClientEntity($clientId);
    $scope = new Scope('companion:device');
    $userIdentifier = (string) $this->createUser()->getAuthIdentifier();
    $grantId = (string) Str::uuid7();
    $codeId = str_repeat('c', 80);
    $selection = new TokenResourceSelectionData(COMPANION_RESOURCE, $scope->getIdentifier());
    request()->attributes->set(TokenResourceSelectionData::REQUEST_ATTRIBUTE, $selection);
    if ($state !== 'no exchange') {
        OAuthAuthCodeExchange::query()->create(['auth_code_id' => $codeId, 'grant_id' => $grantId]);
    }

    if ($state !== 'no grant') {
        $this->grantStore()->seed(new GrantRecord(
            id: $grantId,
            clientId: $state === 'another client' ? (string) $this->createClient()->getKey() : $clientId,
            userIdentifier: $state === 'another user' ? 'another-principal' : $userIdentifier,
            revoked: $state === 'revoked',
            scopes: ['mcp:read'],
            authorizedAt: null,
            lastUsedAt: null,
            resourceScopes: $state === 'other scope' ? [COMPANION_RESOURCE => 'different:scope'] : [COMPANION_RESOURCE => $scope->getIdentifier()],
        ));
    }

    $scopeRepository = app(ResourceScopeRepository::class);
    $finalize = fn (): array => $scopeRepository->finalizeScopes(
        $state === 'missing scope' ? [] : [$scope],
        'authorization_code',
        $clientEntity,
        $userIdentifier,
        $state === 'not consumed' ? null : $codeId,
    );

    if ($state === 'approved' || $state === 'not consumed') {
        expect($finalize())->toBe([$scope])
            ->and(TokenResourceSelectionData::from(request())?->grantId)->toBe($state === 'approved' ? $grantId : null);

        return;
    }

    expect($finalize)->toThrow(
        function (OAuthServerException $exception) use ($state): void {
            if ($state === 'missing scope') {
                expect($exception->getErrorType())->toBe('invalid_scope');

                return;
            }

            expect($exception->getErrorType())->toBe('invalid_target')
                ->and($exception->getCode())->toBe(0);
        },
    );
})->with(['approved', 'not consumed', 'revoked', 'no exchange', 'no grant', 'another client', 'another user', 'other scope', 'missing scope']);

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
