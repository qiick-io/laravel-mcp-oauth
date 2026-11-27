<?php

declare(strict_types=1);

use Qiick\McpOAuth\Contracts\ClientMetadataDocumentFetcherContract;
use Qiick\McpOAuth\Data\ClientMetadataDocumentData;
use Qiick\McpOAuth\Enums\ClientMetadataFetchStatusEnum;
use Qiick\McpOAuth\McpOAuthRoutes;
use Qiick\McpOAuth\Models\OAuthClientMetadata;
use Qiick\McpOAuth\Tests\Support\AuthorizeFlowTestCase;

uses(AuthorizeFlowTestCase::class);

const CIMD_CLIENT_IDENTIFIER = 'https://client.example/oauth-client.json';

function metadataAuthorizeUrl(): string
{
    return '/oauth/authorize?'.http_build_query([
        'response_type' => 'code',
        'client_id' => CIMD_CLIENT_IDENTIFIER,
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
    $this->travel(3)->seconds();
    $this->get(metadataAuthorizeUrl())->assertServiceUnavailable();
    expect($metadata->refresh()->getAttribute('metadata_document'))->toBe($validated)
        ->and($metadata->getAttribute('metadata_document_status'))->toBe('fetch_failed');

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
    expect($metadata->getAttribute('metadata_document'))->toBeNull()
        ->and($metadata->getAttribute('metadata_document_expires_at'))->toBeNull();

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
