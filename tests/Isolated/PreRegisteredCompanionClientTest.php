<?php

declare(strict_types=1);

use Illuminate\Http\Request;
use Laravel\Passport\Client;
use Laravel\Passport\Passport;
use Qiick\McpOAuth\AccessTokenAuthenticator;
use Qiick\McpOAuth\Contracts\ClientMetadataDocumentFetcherContract;
use Qiick\McpOAuth\Data\ClientMetadataDocumentData;
use Qiick\McpOAuth\Data\CompanionClientDefinitionData;
use Qiick\McpOAuth\Data\GrantRecord;
use Qiick\McpOAuth\Enums\ClientMetadataFetchStatusEnum;
use Qiick\McpOAuth\McpOAuthRoutes;
use Qiick\McpOAuth\McpOAuthServer;
use Qiick\McpOAuth\Models\OAuthClientMetadata;
use Qiick\McpOAuth\Tests\Support\AuthorizeFlowTestCase;

uses(AuthorizeFlowTestCase::class);

const PINNED_COMPANION_IDENTIFIER = 'https://companion.qiick.io/oauth/client-metadata.json';
const PINNED_COMPANION_CALLBACK = 'https://companion.qiick.io/oauth/callback';

function registerPinnedCompanion(): Client
{
    app(McpOAuthServer::class)->registerCompanionClient(new CompanionClientDefinitionData(
        PINNED_COMPANION_IDENTIFIER, 'qiick Companion', [PINNED_COMPANION_CALLBACK], 'qiick',
    ));

    return (new Client)->forceFill(['id' => PINNED_COMPANION_IDENTIFIER]);
}

it('uses shipped public metadata with CIMD fetching disabled and supplies the exact issuer', function (): void {
    $this->enableOAuth();
    config()->set('mcp-oauth.companion.enabled', true);
    $this->mock(ClientMetadataDocumentFetcherContract::class)->shouldReceive('fetch')->never();
    $client = registerPinnedCompanion();
    McpOAuthRoutes::register();

    $issuer = app(McpOAuthServer::class)->issuer();
    $this->get('/.well-known/oauth-authorization-server')->assertOk()
        ->assertJsonPath('issuer', $issuer)
        ->assertJsonPath('authorization_response_iss_parameter_supported', true);

    $page = $this->actingAs($this->createUser())->get($this->authorizeUrl($client, [
        'redirect_uri' => PINNED_COMPANION_CALLBACK,
        'install_id' => 'edb06dcc-75b5-4af4-b08e-25393e025fa2',
        'companion_jkt' => '0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2ai4EcM',
    ]), ['X-Inertia' => 'true'])->assertOk()
        ->assertJsonPath('props.client.name', 'qiick Companion')
        ->assertJsonPath('props.client.nameIsSelfAsserted', false)
        ->assertJsonPath('props.client.operatorName', 'qiick')
        ->assertJsonFragment(['notices' => ['Pair this phone.', 'Operated by qiick.']])
        ->assertJsonPath('props.isInstallationPairing', true);

    $approval = $this->post('/oauth/authorize', [
        'auth_token' => $page->json('props.authToken'),
        'scopes' => ['mcp:read'],
        'role' => 'editor',
        'resources' => ['news'],
    ])->assertRedirectContains(PINNED_COMPANION_CALLBACK.'?');
    parse_str((string) parse_url((string) $approval->headers->get('Location'), PHP_URL_QUERY), $parameters);
    expect($parameters['iss'])->toBe($issuer)
        ->and(OAuthClientMetadata::query()->sole()->getAttribute('registration_source'))->toBe('companion');
    $tokenRequest = $this->codeExchange($client, $parameters['code'], ['redirect_uri' => PINNED_COMPANION_CALLBACK]);
    $tokens = $this->post('/oauth/token', $tokenRequest)->assertOk();
    $bearer = Request::create('/mcp', server: ['HTTP_AUTHORIZATION' => 'Bearer '.$tokens->json('access_token')]);
    expect(app(AccessTokenAuthenticator::class)->authenticate($bearer))->toBeInstanceOf(GrantRecord::class);

    $registered = Passport::client()->newQuery()->sole();
    $registered->forceFill(['redirect_uris' => ['https://other.example/callback']])->save();
    expect(app(AccessTokenAuthenticator::class)->authenticate($bearer))->not->toBeInstanceOf(GrantRecord::class);
    $registered->forceFill(['redirect_uris' => [PINNED_COMPANION_CALLBACK]])->save();

    config()->set('mcp-oauth.companion.enabled', false);
    $this->post('/oauth/token', $tokenRequest)->assertUnauthorized()->assertJsonPath('error', 'invalid_client');
    $this->post('/oauth/token', [
        'grant_type' => 'refresh_token',
        'client_id' => PINNED_COMPANION_IDENTIFIER,
        'resource' => AuthorizeFlowTestCase::RESOURCE,
        'refresh_token' => $tokens->json('refresh_token'),
    ])->assertUnauthorized()->assertJsonPath('error', 'invalid_client');
    expect(app(AccessTokenAuthenticator::class)->authenticate($bearer))->not->toBeInstanceOf(GrantRecord::class);
});

it('reserves a disabled first-party identifier from outbound and DCR', function (): void {
    $this->enableOAuth();
    config()->set('mcp-oauth.companion.enabled', false);
    config()->set('mcp-oauth.cimd.enabled', true);
    $this->mock(ClientMetadataDocumentFetcherContract::class)->shouldReceive('fetch')->never();
    $client = registerPinnedCompanion();
    McpOAuthRoutes::register();

    $this->get($this->authorizeUrl($client, ['redirect_uri' => PINNED_COMPANION_CALLBACK]))
        ->assertBadRequest()->assertJsonPath('error', 'invalid_client')->assertHeaderMissing('Location');
    $this->postJson('/oauth/register', [
        'client_id' => PINNED_COMPANION_IDENTIFIER,
        'client_name' => 'Other app',
        'redirect_uris' => ['https://other.example/callback'],
        'grant_types' => ['authorization_code', 'refresh_token'],
        'token_endpoint_auth_method' => 'none',
    ])->assertBadRequest()->assertJsonPath('error', 'invalid_client_metadata');
    expect(OAuthClientMetadata::query()->exists())->toBeFalse();
});

it('does not accept a fetched document claiming the reserved identifier', function (): void {
    $this->enableOAuth();
    config()->set('mcp-oauth.companion.enabled', true);
    config()->set('mcp-oauth.cimd.enabled', true);
    $foreignIdentifier = 'https://other.example/client.json';
    $this->mock(ClientMetadataDocumentFetcherContract::class)->shouldReceive('fetch')
        ->once()->with($foreignIdentifier, null)->andReturn(new ClientMetadataDocumentData(
            ClientMetadataFetchStatusEnum::Fetched,
            [
                'client_id' => PINNED_COMPANION_IDENTIFIER,
                'client_name' => 'Untrusted client',
                'redirect_uris' => [PINNED_COMPANION_CALLBACK],
            ],
        ));
    $client = registerPinnedCompanion();
    McpOAuthRoutes::register();

    $this->get($this->authorizeUrl($client, [
        'client_id' => $foreignIdentifier,
        'redirect_uri' => PINNED_COMPANION_CALLBACK,
    ]))->assertBadRequest()->assertJsonPath('error', 'invalid_client')->assertHeaderMissing('Location');
    expect(OAuthClientMetadata::query()->exists())->toBeFalse();
});

it('rejects incomplete metadata declarations before registering the first-party identifier', function (string $identifier, string $name, array $redirectUris, string $operator): void {
    $definition = new CompanionClientDefinitionData($identifier, $name, $redirectUris, $operator);

    expect(fn () => app(McpOAuthServer::class)->registerCompanionClient($definition))
        ->toThrow(InvalidArgumentException::class);
    expect(OAuthClientMetadata::query()->exists())->toBeFalse();
})->with([
    'identifier without path' => ['https://companion.qiick.io', 'qiick Companion', [PINNED_COMPANION_CALLBACK], 'qiick'],
    'identifier with query' => [PINNED_COMPANION_IDENTIFIER.'?other=one', 'qiick Companion', [PINNED_COMPANION_CALLBACK], 'qiick'],
    'blank name' => [PINNED_COMPANION_IDENTIFIER, ' ', [PINNED_COMPANION_CALLBACK], 'qiick'],
    'oversized name' => [PINNED_COMPANION_IDENTIFIER, str_repeat('n', 256), [PINNED_COMPANION_CALLBACK], 'qiick'],
    'blank operator' => [PINNED_COMPANION_IDENTIFIER, 'qiick Companion', [PINNED_COMPANION_CALLBACK], ' '],
    'missing callbacks' => [PINNED_COMPANION_IDENTIFIER, 'qiick Companion', [], 'qiick'],
    'loopback callback' => [PINNED_COMPANION_IDENTIFIER, 'qiick Companion', ['http://127.0.0.1/callback'], 'qiick'],
    'custom-scheme callback' => [PINNED_COMPANION_IDENTIFIER, 'qiick Companion', ['io.qiick.companion:/callback'], 'qiick'],
    'oversized HTTPS callback' => [PINNED_COMPANION_IDENTIFIER, 'qiick Companion', [PINNED_COMPANION_CALLBACK.str_repeat('r', 1025 - strlen(PINNED_COMPANION_CALLBACK))], 'qiick'],
]);

it('reserves distinct companion identifiers at the declared size limits without creating clients', function (): void {
    $server = app(McpOAuthServer::class);
    $identifier = PINNED_COMPANION_IDENTIFIER.str_repeat('i', 2048 - strlen(PINNED_COMPANION_IDENTIFIER));
    $callback = PINNED_COMPANION_CALLBACK.str_repeat('r', 1024 - strlen(PINNED_COMPANION_CALLBACK));
    $definition = new CompanionClientDefinitionData($identifier, str_repeat('n', 255), [$callback], 'qiick');
    $server->registerCompanionClient($definition);
    registerPinnedCompanion();

    expect($server->companionClientFor($identifier))->toBe($definition)
        ->and($server->companionClientFor(PINNED_COMPANION_IDENTIFIER)?->redirectUris)->toBe([PINNED_COMPANION_CALLBACK])
        ->and(fn () => $server->registerCompanionClient($definition))->toThrow(InvalidArgumentException::class)
        ->and(fn () => $server->registerCompanionClient(new CompanionClientDefinitionData(
            $server->resourceIdentifier(), 'Resource', [$callback], 'qiick',
        )))->toThrow(InvalidArgumentException::class)
        ->and(OAuthClientMetadata::query()->exists())->toBeFalse();
});

it('replies to denial with the exact issuer and refuses callbacks outside the shipped list', function (): void {
    $this->enableOAuth();
    config()->set('mcp-oauth.companion.enabled', true);
    $client = registerPinnedCompanion();
    McpOAuthRoutes::register();
    $this->actingAs($this->createUser());
    $authorization = [
        'redirect_uri' => PINNED_COMPANION_CALLBACK,
        'install_id' => 'edb06dcc-75b5-4af4-b08e-25393e025fa2',
        'companion_jkt' => '0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2ai4EcM',
    ];

    foreach (['https://other.example/callback', 'https://Companion.qiick.io/oauth/callback'] as $unlistedCallback) {
        $this->get($this->authorizeUrl($client, [...$authorization, 'redirect_uri' => $unlistedCallback]))
            ->assertBadRequest()->assertJsonPath('error', 'invalid_request')->assertHeaderMissing('Location');
    }

    $page = $this->get($this->authorizeUrl($client, $authorization), ['X-Inertia' => 'true'])->assertOk();
    $denial = $this->delete('/oauth/authorize', ['auth_token' => $page->json('props.authToken')])
        ->assertRedirectContains(PINNED_COMPANION_CALLBACK.'?');
    parse_str((string) parse_url((string) $denial->headers->get('Location'), PHP_URL_QUERY), $parameters);
    expect($parameters['error'])->toBe('access_denied')
        ->and($parameters['iss'])->toBe(app(McpOAuthServer::class)->issuer());
});

it('replaces a previously fetched registration with the shipped definition and retires its credentials', function (): void {
    $this->enableOAuth();
    config()->set('mcp-oauth.cimd.enabled', true);
    config()->set('mcp-oauth.companion.enabled', true);
    $this->mock(ClientMetadataDocumentFetcherContract::class)->shouldReceive('fetch')->never();
    McpOAuthRoutes::register();

    $previousClient = $this->createClient();
    ['code' => $previousCode, 'user' => $user] = $this->obtainAuthorizationCode($previousClient);
    $previousTokens = $this->post('/oauth/token', $this->codeExchange($previousClient, $previousCode))->assertOk();
    $unexchangedCode = Passport::authCode()->forceFill([
        'id' => str_repeat('a', 80),
        'user_id' => $user->getAuthIdentifier(),
        'client_id' => $previousClient->getKey(),
        'scopes' => json_encode(['mcp:use'], JSON_THROW_ON_ERROR),
        'revoked' => false,
        'expires_at' => now()->addMinutes(5),
    ]);
    $unexchangedCode->save();
    $previousMetadata = OAuthClientMetadata::query()->sole();
    $previousMetadata->update([
        'registration_source' => 'cimd',
        'spec_revision' => 'legacy',
        'application_type' => 'web',
        'token_endpoint_auth_method' => null,
        'metadata_document_url' => PINNED_COMPANION_IDENTIFIER,
        'metadata_document_url_sha256' => hash('sha256', PINNED_COMPANION_IDENTIFIER),
        'metadata_document' => ['client_id' => PINNED_COMPANION_IDENTIFIER],
        'metadata_document_sha256' => hash('sha256', PINNED_COMPANION_IDENTIFIER),
        'metadata_document_status' => 'valid',
        'metadata_document_error' => 'previous error',
        'metadata_document_etag' => '"previous-metadata"',
        'metadata_document_fetched_at' => now()->subHour(),
        'metadata_document_expires_at' => now()->addHour(),
    ]);
    $bearer = Request::create('/mcp', server: ['HTTP_AUTHORIZATION' => 'Bearer '.$previousTokens->json('access_token')]);
    $authenticator = app(AccessTokenAuthenticator::class);
    expect($authenticator->authenticate($bearer))->toBeInstanceOf(GrantRecord::class);

    $pinnedClient = registerPinnedCompanion();
    expect($authenticator->authenticate($bearer))->not->toBeInstanceOf(GrantRecord::class);
    $this->get($this->authorizeUrl($pinnedClient, ['redirect_uri' => AuthorizeFlowTestCase::REGISTERED_REDIRECT_URI]))
        ->assertBadRequest()->assertJsonPath('error', 'invalid_request')->assertHeaderMissing('Location');

    $pinnedMetadata = OAuthClientMetadata::query()->sole();
    $storedClient = Passport::client()->newQuery()->sole();
    expect($pinnedMetadata->getKey())->toBe($previousMetadata->getKey())
        ->and($pinnedMetadata->getAttribute('registration_source'))->toBe('companion')
        ->and($pinnedMetadata->getAttribute('spec_revision'))->toBe(app(McpOAuthServer::class)->specRevision())
        ->and($pinnedMetadata->getAttribute('application_type'))->toBe('native')
        ->and($pinnedMetadata->getAttribute('token_endpoint_auth_method'))->toBe('none')
        ->and($pinnedMetadata->getAttribute('has_per_install_grants'))->toBeTrue()
        ->and($storedClient->getKey())->toBe($previousClient->getKey())
        ->and($storedClient->getAttribute('name'))->toBe('qiick Companion')
        ->and($storedClient->getAttribute('grant_types'))->toBe(['authorization_code', 'refresh_token'])
        ->and($storedClient->getAttribute('secret'))->toBeNull()
        ->and($storedClient->getAttribute('redirect_uris'))->toBe([PINNED_COMPANION_CALLBACK])
        ->and(Passport::token()->newQuery()->sole()->getAttribute('revoked'))->toBeTrue()
        ->and(Passport::refreshToken()->newQuery()->sole()->getAttribute('revoked'))->toBeTrue()
        ->and($unexchangedCode->refresh()->getAttribute('revoked'))->toBeTrue();

    foreach (['document', 'document_sha256', 'document_etag', 'document_fetched_at', 'document_expires_at', 'document_status', 'document_error'] as $field) {
        expect($pinnedMetadata->getAttribute('metadata_'.$field))->toBeNull();
    }
});
