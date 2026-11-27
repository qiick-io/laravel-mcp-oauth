<?php

declare(strict_types=1);

use Illuminate\Http\Request;
use Laravel\Passport\Passport;
use Qiick\McpOAuth\AccessTokenAuthenticator;
use Qiick\McpOAuth\Contracts\ClientMetadataDocumentFetcherContract;
use Qiick\McpOAuth\Data\AuthorizationDecision;
use Qiick\McpOAuth\Data\ClientMetadataDocumentData;
use Qiick\McpOAuth\Data\GrantRecord;
use Qiick\McpOAuth\Enums\ClientMetadataFetchStatusEnum;
use Qiick\McpOAuth\McpOAuthRoutes;
use Qiick\McpOAuth\Models\OAuthClientMetadata;
use Qiick\McpOAuth\Tests\Support\AuthorizeFlowTestCase;

uses(AuthorizeFlowTestCase::class);

const CIMD_CLIENT_IDENTIFIER = 'https://client.example/oauth-client.json';

function metadataAuthorizeUrl(string $identifier = CIMD_CLIENT_IDENTIFIER): string
{
    return '/oauth/authorize?'.http_build_query([
        'response_type' => 'code',
        'client_id' => $identifier,
        'redirect_uri' => AuthorizeFlowTestCase::REGISTERED_REDIRECT_URI,
        'code_challenge' => AuthorizeFlowTestCase::CODE_CHALLENGE,
        'code_challenge_method' => 'S256',
        'resource' => AuthorizeFlowTestCase::RESOURCE,
    ]);
}

beforeEach(function (): void {
    McpOAuthRoutes::register();
    $this->enableOAuth();
});

it('advertises CIMD only while enabled', function (): void {
    $this->get('/.well-known/oauth-authorization-server')
        ->assertOk()
        ->assertJsonMissingPath('client_id_metadata_document_supported');

    config()->set('mcp-oauth.cimd.enabled', true);
    $this->mock(ClientMetadataDocumentFetcherContract::class);

    $this->get('/.well-known/oauth-authorization-server')
        ->assertOk()
        ->assertJsonPath('client_id_metadata_document_supported', true);
});

it('registers the exact URL once and accepts it on authorize, exchange, refresh and revoke', function (): void {
    config()->set('mcp-oauth.cimd.enabled', true);
    $fetcher = $this->mock(ClientMetadataDocumentFetcherContract::class);
    $fetcher->shouldReceive('fetch')->once()->with(CIMD_CLIENT_IDENTIFIER, null)->andReturn(
        new ClientMetadataDocumentData(ClientMetadataFetchStatusEnum::Fetched, [
            'client_id' => CIMD_CLIENT_IDENTIFIER,
            'client_name' => 'Document client',
            'redirect_uris' => [AuthorizeFlowTestCase::REGISTERED_REDIRECT_URI],
            'grant_types' => ['authorization_code', 'refresh_token'],
        ], etag: '"version-one"', maxAgeSeconds: 120),
    );

    $consent = $this->actingAs($this->createUser())
        ->get(metadataAuthorizeUrl(), ['X-Inertia' => 'true'])
        ->assertOk()
        ->assertJsonPath('props.client.name', 'Document client');
    $approval = $this->post('/oauth/authorize', [
        'auth_token' => $consent->json('props.authToken'),
        'scopes' => ['mcp:read'],
        'role' => 'editor',
        'resources' => ['news'],
    ])->assertRedirect();
    parse_str((string) parse_url((string) $approval->headers->get('Location'), PHP_URL_QUERY), $redirectParameters);
    $this->app['auth']->forgetGuards();
    $this->flushSession();

    $tokens = $this->post('/oauth/token', [
        'client_id' => CIMD_CLIENT_IDENTIFIER,
        'grant_type' => 'authorization_code',
        'code' => $redirectParameters['code'],
        'code_verifier' => AuthorizeFlowTestCase::CODE_VERIFIER,
        'redirect_uri' => AuthorizeFlowTestCase::REGISTERED_REDIRECT_URI,
        'resource' => AuthorizeFlowTestCase::RESOURCE,
    ])->assertOk();
    $metadata = OAuthClientMetadata::query()->sole();
    expect($metadata->getAttribute('registration_source'))->toBe('cimd')
        ->and($metadata->getAttribute('metadata_document_url'))->toBe(CIMD_CLIENT_IDENTIFIER)
        ->and($metadata->getAttribute('metadata_document_etag'))->toBe('"version-one"');

    $refresh = [
        'client_id' => $metadata->getAttribute('client_id'),
        'grant_type' => 'refresh_token',
        'refresh_token' => $tokens->json('refresh_token'),
        'resource' => AuthorizeFlowTestCase::RESOURCE,
    ];
    $this->post('/oauth/token', $refresh)->assertUnauthorized()->assertJsonPath('error', 'invalid_client');
    $refresh['client_id'] = CIMD_CLIENT_IDENTIFIER;
    $rotated = $this->post('/oauth/token', $refresh)->assertOk();

    $this->post('/oauth/revoke', [
        'client_id' => CIMD_CLIENT_IDENTIFIER,
        'token' => $rotated->json('refresh_token'),
    ])->assertOk();
});

it('refuses mismatched client ids and transport failures locally without registering or redirecting', function (string $status, int $httpStatus, string $error): void {
    config()->set('mcp-oauth.cimd.enabled', true);
    $fetcher = $this->mock(ClientMetadataDocumentFetcherContract::class);
    $fetcher->shouldReceive('fetch')->once()->with(CIMD_CLIENT_IDENTIFIER, null)->andReturn(
        new ClientMetadataDocumentData(ClientMetadataFetchStatusEnum::from($status), [
            'client_id' => 'https://client.example:443/oauth-client.json',
            'redirect_uris' => [AuthorizeFlowTestCase::REGISTERED_REDIRECT_URI],
        ]),
    );

    $result = $this->get(metadataAuthorizeUrl())->assertStatus($httpStatus)->assertJsonPath('error', $error);

    expect($result->headers->has('Location'))->toBeFalse()
        ->and(OAuthClientMetadata::query()->exists())->toBeFalse();

    $this->get(metadataAuthorizeUrl())->assertStatus($httpStatus)->assertJsonPath('error', $error);
})->with([
    'different exact identifier' => ['fetched', 400, 'invalid_client'],
    'transient transport failure' => ['unavailable', 503, 'temporarily_unavailable'],
]);

it('keeps the last good document on an outage and revalidates expired data with the ETag', function (): void {
    config()->set('mcp-oauth.cimd.enabled', true);
    $fetcher = $this->mock(ClientMetadataDocumentFetcherContract::class);
    $fetcher->shouldReceive('fetch')->once()->with(CIMD_CLIENT_IDENTIFIER, null)->andReturn(
        new ClientMetadataDocumentData(ClientMetadataFetchStatusEnum::Fetched, [
            'client_id' => CIMD_CLIENT_IDENTIFIER,
            'redirect_uris' => [AuthorizeFlowTestCase::REGISTERED_REDIRECT_URI],
        ], etag: '"one"', maxAgeSeconds: 2),
    );
    $fetcher->shouldReceive('fetch')->twice()->with(CIMD_CLIENT_IDENTIFIER, '"one"')->andReturn(
        new ClientMetadataDocumentData(ClientMetadataFetchStatusEnum::Unavailable),
        new ClientMetadataDocumentData(ClientMetadataFetchStatusEnum::NotModified),
    );

    $this->actingAs($this->createUser())->get(metadataAuthorizeUrl(), ['X-Inertia' => 'true'])->assertOk();
    $metadata = OAuthClientMetadata::query()->sole();
    $validated = $metadata->getAttribute('metadata_document');
    $this->travel(1)->seconds();
    $this->get(metadataAuthorizeUrl(), ['X-Inertia' => 'true'])->assertOk();
    $this->travel(61)->seconds();
    $this->get(metadataAuthorizeUrl())->assertServiceUnavailable();
    expect($metadata->refresh()->getAttribute('metadata_document'))->toBe($validated)
        ->and($metadata->getAttribute('metadata_document_status'))->toBe('fetch_failed');

    $this->get(metadataAuthorizeUrl())->assertServiceUnavailable();
    $this->travel(61)->seconds();
    $this->get(metadataAuthorizeUrl(), ['X-Inertia' => 'true'])->assertOk();
    $this->travel(1)->seconds();
    $this->get(metadataAuthorizeUrl(), ['X-Inertia' => 'true'])->assertOk();
    expect($metadata->refresh()->getAttribute('metadata_document'))->toBe($validated)
        ->and($metadata->getAttribute('metadata_document_status'))->toBe('valid');
});

it('demands new consent when the document replaces the callback before approval', function (): void {
    config()->set('mcp-oauth.cimd.enabled', true);
    $fetcher = $this->mock(ClientMetadataDocumentFetcherContract::class);
    $fetcher->shouldReceive('fetch')->twice()->with(CIMD_CLIENT_IDENTIFIER, null)->andReturn(
        new ClientMetadataDocumentData(ClientMetadataFetchStatusEnum::Fetched, [
            'client_id' => CIMD_CLIENT_IDENTIFIER,
            'redirect_uris' => [AuthorizeFlowTestCase::REGISTERED_REDIRECT_URI],
        ], shouldCache: false),
        new ClientMetadataDocumentData(ClientMetadataFetchStatusEnum::Fetched, [
            'client_id' => CIMD_CLIENT_IDENTIFIER,
            'redirect_uris' => ['https://app.example/new-callback'],
        ]),
    );

    $consent = $this->actingAs($this->createUser())->get(metadataAuthorizeUrl(), ['X-Inertia' => 'true'])->assertOk();
    $metadata = OAuthClientMetadata::query()->sole();
    expect($metadata->getAttribute('metadata_document'))->toBeNull();
    $this->get(metadataAuthorizeUrl(), ['X-Inertia' => 'true'])->assertOk();
    $consent = $this->get(metadataAuthorizeUrl(), ['X-Inertia' => 'true'])->assertOk();
    $this->travel(61)->seconds();

    $this->post('/oauth/authorize', [
        'auth_token' => $consent->json('props.authToken'),
        'scopes' => ['mcp:read'],
        'role' => 'editor',
        'resources' => ['news'],
    ])->assertForbidden()->assertHeaderMissing('Location');

    expect($this->grantStore()->replacedDecisions)->toBeEmpty();
});

it('applies the configured callback domains before associating a client', function (): void {
    config()->set('mcp-oauth.cimd.enabled', true);
    config()->set('mcp.redirect_domains', ['https://other.example']);
    $fetcher = $this->mock(ClientMetadataDocumentFetcherContract::class);
    $fetcher->shouldReceive('fetch')->once()->with(CIMD_CLIENT_IDENTIFIER, null)->andReturn(
        new ClientMetadataDocumentData(ClientMetadataFetchStatusEnum::Fetched, [
            'client_id' => CIMD_CLIENT_IDENTIFIER,
            'redirect_uris' => [AuthorizeFlowTestCase::REGISTERED_REDIRECT_URI],
        ]),
    );

    $this->get(metadataAuthorizeUrl())->assertBadRequest()->assertJsonPath('error', 'invalid_client');
    expect(OAuthClientMetadata::query()->exists())->toBeFalse();
});

it('refuses authentication methods other than none before showing consent', function (array $authentication): void {
    config()->set('mcp-oauth.cimd.enabled', true);
    $fetcher = $this->mock(ClientMetadataDocumentFetcherContract::class);
    $fetcher->shouldReceive('fetch')->once()->andReturn(new ClientMetadataDocumentData(ClientMetadataFetchStatusEnum::Fetched, [
        'client_id' => CIMD_CLIENT_IDENTIFIER,
        'redirect_uris' => [AuthorizeFlowTestCase::REGISTERED_REDIRECT_URI],
        ...$authentication,
    ]));

    $this->get(metadataAuthorizeUrl())->assertBadRequest()->assertJsonPath('error', 'invalid_client');
    expect(OAuthClientMetadata::query()->exists())->toBeFalse();
})->with([
    'explicit assertion method' => [['token_endpoint_auth_method' => 'private_key_jwt', 'token_endpoint_auth_methods_supported' => ['none', 'private_key_jwt']]],
    'offers assertion method' => [['token_endpoint_auth_methods_supported' => ['none', 'private_key_jwt']]],
]);

it('rejects a dot segment before making an HTTP request', function (string $segment): void {
    config()->set('mcp-oauth.cimd.enabled', true);
    $this->mock(ClientMetadataDocumentFetcherContract::class)->shouldNotReceive('fetch');

    $this->get(metadataAuthorizeUrl('https://client.example/folder/'.$segment.'/client.json'))->assertBadRequest()->assertJsonPath('error', 'invalid_client');
})->with(['.', '..', '%2e', '.%2E']);

it('uses the minimum fetch interval for a zero freshness lifetime', function (): void {
    config()->set('mcp-oauth.cimd.enabled', true);
    $this->mock(ClientMetadataDocumentFetcherContract::class)->shouldReceive('fetch')->once()->andReturn(
        new ClientMetadataDocumentData(ClientMetadataFetchStatusEnum::Fetched, [
            'client_id' => CIMD_CLIENT_IDENTIFIER,
            'redirect_uris' => [AuthorizeFlowTestCase::REGISTERED_REDIRECT_URI],
        ], maxAgeSeconds: 0),
    );

    $this->actingAs($this->createUser())->get(metadataAuthorizeUrl(), ['X-Inertia' => 'true'])->assertOk();
    $this->travel(30)->seconds();
    $this->get(metadataAuthorizeUrl(), ['X-Inertia' => 'true'])->assertOk();
});

it('revokes issued tokens when the refreshed callback policy changes or becomes invalid', function (string $fetchStatus): void {
    config()->set('mcp-oauth.cimd.enabled', true);
    $client = $this->createClient();
    ['code' => $code] = $this->obtainAuthorizationCode($client);
    $tokens = $this->post('/oauth/token', $this->codeExchange($client, $code))->assertOk();

    $metadata = OAuthClientMetadata::query()->sole();
    $metadata->update([
        'registration_source' => 'cimd',
        'metadata_document_url' => CIMD_CLIENT_IDENTIFIER,
        'metadata_document_url_sha256' => hash('sha256', CIMD_CLIENT_IDENTIFIER),
        'metadata_document_status' => 'valid',
        'metadata_document_expires_at' => now()->subSecond(),
    ]);

    $bearerRequest = Request::create('/mcp', server: ['HTTP_AUTHORIZATION' => 'Bearer '.$tokens->json('access_token')]);
    $authenticator = app(AccessTokenAuthenticator::class);
    $fetcher = $this->mock(ClientMetadataDocumentFetcherContract::class);
    $fetcher->shouldReceive('fetch')->once()->andReturn(new ClientMetadataDocumentData(ClientMetadataFetchStatusEnum::from($fetchStatus), [
        'client_id' => CIMD_CLIENT_IDENTIFIER,
        'redirect_uris' => ['https://app.example/changed-callback'],
    ]));

    expect($authenticator->authenticate($bearerRequest))->toBeInstanceOf(GrantRecord::class);
    config()->set('mcp-oauth.cimd.enabled', false);
    expect($authenticator->authenticate($bearerRequest))->toBeInstanceOf(AuthorizationDecision::class);
    config()->set('mcp-oauth.cimd.enabled', true);
    $metadata->update(['metadata_document_status' => 'invalid']);
    expect($authenticator->authenticate($bearerRequest))->toBeInstanceOf(AuthorizationDecision::class);
    $metadata->update(['metadata_document_status' => 'valid']);

    $this->get(metadataAuthorizeUrl())->assertBadRequest();

    expect(Passport::token()->newQuery()->sole()->getAttribute('revoked'))->toBeTrue()
        ->and(Passport::refreshToken()->newQuery()->sole()->getAttribute('revoked'))->toBeTrue()
        ->and($authenticator->authenticate($bearerRequest))->toBeInstanceOf(AuthorizationDecision::class);
})->with(['fetched', 'invalid']);
