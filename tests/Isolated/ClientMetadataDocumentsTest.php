<?php

declare(strict_types=1);

use Illuminate\Database\Events\TransactionRolledBack;
use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Event;
use Laravel\Passport\Client;
use Laravel\Passport\ClientRepository;
use Laravel\Passport\Passport;
use Qiick\McpOAuth\AccessTokenAuthenticator;
use Qiick\McpOAuth\Contracts\ClientMetadataDocumentFetcherContract;
use Qiick\McpOAuth\Data\AuthorizationDecision;
use Qiick\McpOAuth\Data\ClientMetadataDocumentData;
use Qiick\McpOAuth\Data\GrantRecord;
use Qiick\McpOAuth\Enums\ClientMetadataFetchStatusEnum;
use Qiick\McpOAuth\Exceptions\ClientMetadataUnavailableException;
use Qiick\McpOAuth\Http\Middleware\ValidateAuthorizationRequestMiddleware;
use Qiick\McpOAuth\Http\Middleware\ValidateTokenRequestMiddleware;
use Qiick\McpOAuth\McpOAuthRoutes;
use Qiick\McpOAuth\Models\OAuthBlockedRedirectHost;
use Qiick\McpOAuth\Models\OAuthClientMetadata;
use Qiick\McpOAuth\Services\ClientMetadataRegistryService;
use Qiick\McpOAuth\Tests\Support\AuthorizeFlowTestCase;
use Symfony\Component\HttpFoundation\Response;

uses(AuthorizeFlowTestCase::class);

const CIMD_CLIENT_IDENTIFIER = 'https://client.example/oauth-client.json';

function metadataAuthorizeUrl(string $identifier = CIMD_CLIENT_IDENTIFIER, string $redirectUri = AuthorizeFlowTestCase::REGISTERED_REDIRECT_URI): string
{
    return '/oauth/authorize?'.http_build_query([
        'response_type' => 'code',
        'client_id' => $identifier,
        'redirect_uri' => $redirectUri,
        'code_challenge' => AuthorizeFlowTestCase::CODE_CHALLENGE,
        'code_challenge_method' => 'S256',
        'resource' => AuthorizeFlowTestCase::RESOURCE,
    ]);
}

/** Adds the wire identifier to an existing Passport client fixture. */
function identifyAsMetadataClient(Client $client, bool $isExpired = false): OAuthClientMetadata
{
    $metadata = OAuthClientMetadata::query()->where('client_id', $client->getKey())->firstOrFail();
    $metadata->update([
        'registration_source' => 'cimd',
        'metadata_document_url' => CIMD_CLIENT_IDENTIFIER,
        'metadata_document_url_sha256' => hash('sha256', CIMD_CLIENT_IDENTIFIER),
        'metadata_document_status' => 'valid',
        'metadata_document_expires_at' => now()->addSeconds($isExpired ? -1 : 120),
    ]);

    return $metadata;
}

/** @param array<string, mixed> $documentFields */
function fetchedMetadata(array $documentFields = [], ?int $maxAgeSeconds = null, bool $shouldCache = true): ClientMetadataDocumentData
{
    return new ClientMetadataDocumentData(ClientMetadataFetchStatusEnum::Fetched, [
        'client_id' => CIMD_CLIENT_IDENTIFIER,
        'redirect_uris' => [AuthorizeFlowTestCase::REGISTERED_REDIRECT_URI],
        ...$documentFields,
    ], etag: '"validator"', maxAgeSeconds: $maxAgeSeconds, shouldCache: $shouldCache);
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
        ->assertJsonPath('props.client.name', 'Document client')
        ->assertJsonPath('props.advanced.0.value', CIMD_CLIENT_IDENTIFIER);
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

    $revocation = [
        'client_id' => CIMD_CLIENT_IDENTIFIER,
        'token' => $rotated->json('refresh_token'),
    ];
    $this->post('/oauth/revoke', [...$revocation, 'client_secret' => 'unsupported'])->assertUnauthorized();
    $this->post('/oauth/revoke', $revocation)->assertOk();
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

it('compares the metadata callback literally before handing off to Passport', function (): void {
    config()->set('mcp-oauth.cimd.enabled', true);
    $this->mock(ClientMetadataDocumentFetcherContract::class)->shouldNotReceive('fetch');
    $client = $this->createClient();
    identifyAsMetadataClient($client);

    $this->get(metadataAuthorizeUrl(redirectUri: 'https://APP.EXAMPLE/callback'))
        ->assertBadRequest()
        ->assertJsonPath('error', 'invalid_request')
        ->assertHeader('Cache-Control', 'no-store, private')
        ->assertHeaderMissing('Location');
});

it('refuses a metadata client whose Passport model cannot supply a string identifier', function (): void {
    config()->set('mcp-oauth.cimd.enabled', true);
    $this->mock(ClientMetadataDocumentFetcherContract::class)->shouldNotReceive('fetch');
    identifyAsMetadataClient($this->createClient());
    $clientWithIntegerKey = new class extends Client
    {
        protected $table = 'oauth_clients';

        public function getKey(): int
        {
            return 1;
        }
    };
    Passport::useClientModel($clientWithIntegerKey::class);

    try {
        // The vendor may also refuse the rewritten value. Prove that neither
        // middleware forwards an identifier the package cannot represent.
        $downstream = static fn (): Response => new Response(status: 204);
        $authorization = Request::create(metadataAuthorizeUrl());
        $token = Request::create('/oauth/token', 'POST', [
            'client_id' => CIMD_CLIENT_IDENTIFIER,
            'grant_type' => 'refresh_token',
            'refresh_token' => 'unused',
            'resource' => AuthorizeFlowTestCase::RESOURCE,
        ]);

        expect(app(ValidateAuthorizationRequestMiddleware::class)->handle($authorization, $downstream)->getStatusCode())->toBe(400)
            ->and(app(ValidateTokenRequestMiddleware::class)->handle($token, $downstream)->getStatusCode())->toBe(401);
    } finally {
        Passport::useClientModel(Client::class);
    }
});

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
        ->and($metadata->getAttribute('metadata_document_status'))->toBe('fetch_failed')
        ->and($metadata->getAttribute('metadata_document_error'))->toBe('unavailable');

    $this->get(metadataAuthorizeUrl())->assertServiceUnavailable();
    $this->travel(61)->seconds();
    $this->get(metadataAuthorizeUrl(), ['X-Inertia' => 'true'])->assertOk();
    $this->travel(1)->seconds();
    $this->get(metadataAuthorizeUrl(), ['X-Inertia' => 'true'])->assertOk();
    expect($metadata->refresh()->getAttribute('metadata_document'))->toBe($validated)
        ->and($metadata->getAttribute('metadata_document_status'))->toBe('valid')
        ->and($metadata->getAttribute('metadata_document_error'))->toBeNull();
});

it('stops approval when the document changes the callback or becomes unavailable', function (string $fetchStatus, int $httpStatus): void {
    config()->set('mcp-oauth.cimd.enabled', true);
    $fetcher = $this->mock(ClientMetadataDocumentFetcherContract::class);
    $fetcher->shouldReceive('fetch')->twice()->with(CIMD_CLIENT_IDENTIFIER, null)->andReturn(
        new ClientMetadataDocumentData(ClientMetadataFetchStatusEnum::Fetched, [
            'client_id' => CIMD_CLIENT_IDENTIFIER,
            'redirect_uris' => [AuthorizeFlowTestCase::REGISTERED_REDIRECT_URI],
        ], shouldCache: false),
        new ClientMetadataDocumentData(ClientMetadataFetchStatusEnum::from($fetchStatus), [
            'client_id' => CIMD_CLIENT_IDENTIFIER,
            'redirect_uris' => ['https://app.example/new-callback'],
        ]),
    );

    $this->actingAs($this->createUser())->get(metadataAuthorizeUrl(), ['X-Inertia' => 'true'])->assertOk();
    $metadata = OAuthClientMetadata::query()->sole();
    expect($metadata->getAttribute('metadata_document'))->toBeNull();
    $consent = $this->get(metadataAuthorizeUrl(), ['X-Inertia' => 'true'])->assertOk();
    $this->travel(61)->seconds();

    $this->post('/oauth/authorize', [
        'auth_token' => $consent->json('props.authToken'),
        'scopes' => ['mcp:read'],
        'role' => 'editor',
        'resources' => ['news'],
    ])->assertStatus($httpStatus)->assertHeaderMissing('Location');

    expect($this->grantStore()->replacedDecisions)->toBeEmpty();
})->with(['callback replaced' => ['fetched', 403], 'fetch temporarily unavailable' => ['unavailable', 503]]);

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

it('refuses metadata that does not describe a public authorization code client', function (array $documentFields): void {
    config()->set('mcp-oauth.cimd.enabled', true);
    $fetcher = $this->mock(ClientMetadataDocumentFetcherContract::class);
    $fetcher->shouldReceive('fetch')->once()->andReturn(fetchedMetadata($documentFields));

    $this->get(metadataAuthorizeUrl())->assertBadRequest()->assertJsonPath('error', 'invalid_client');
    expect(OAuthClientMetadata::query()->exists())->toBeFalse();
})->with([
    'explicit assertion method' => [['token_endpoint_auth_method' => 'private_key_jwt', 'token_endpoint_auth_methods_supported' => ['none', 'private_key_jwt']]],
    'offers assertion method' => [['token_endpoint_auth_methods_supported' => ['none', 'private_key_jwt']]],
    'null method is explicit' => [['token_endpoint_auth_method' => null]],
    'null method list is explicit' => [['token_endpoint_auth_methods_supported' => null]],
    'contains client secret field' => [['client_secret' => null]],
    'contains secret expiry field' => [['client_secret_expires_at' => null]],
    'lacks the authorization code grant' => [['grant_types' => ['refresh_token']]],
    'lacks the code response' => [['response_types' => ['token']]],
    'empty redirect list' => [['redirect_uris' => []]],
    'redirect map' => [['redirect_uris' => ['default' => AuthorizeFlowTestCase::REGISTERED_REDIRECT_URI]]],
    'non-string redirect' => [['redirect_uris' => [AuthorizeFlowTestCase::REGISTERED_REDIRECT_URI, 123]]],
    'explicitly empty redirect' => [['redirect_uris' => [AuthorizeFlowTestCase::REGISTERED_REDIRECT_URI, '']]],
    'too many redirects' => [['redirect_uris' => array_fill(0, 11, AuthorizeFlowTestCase::REGISTERED_REDIRECT_URI)]],
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

it('bounds freshness and retains only permitted metadata on registration', function (int $maxAge, bool $shouldCache, int $retainedSeconds): void {
    config()->set('mcp-oauth.cimd.enabled', true);
    config()->set('mcp-oauth.cimd.cache_min_seconds', 12);
    config()->set('mcp-oauth.cimd.cache_max_seconds', 30);
    $this->freezeSecond();
    $this->mock(ClientMetadataDocumentFetcherContract::class)->shouldReceive('fetch')->once()->with(CIMD_CLIENT_IDENTIFIER, null)
        ->andReturn(fetchedMetadata([
            'client_name' => 'A client',
            'grant_types' => ['refresh_token', 'client_credentials', 'authorization_code'],
            'extension' => 'metadata we do not persist',
        ], maxAgeSeconds: $maxAge, shouldCache: $shouldCache));

    $registry = app(ClientMetadataRegistryService::class);
    $client = $registry->resolve(CIMD_CLIENT_IDENTIFIER, canRegister: true);
    $metadata = OAuthClientMetadata::query()->sole();
    $retainedDocument = [
        'client_id' => CIMD_CLIENT_IDENTIFIER,
        'client_name' => 'A client',
        'redirect_uris' => [AuthorizeFlowTestCase::REGISTERED_REDIRECT_URI],
        'grant_types' => ['authorization_code', 'refresh_token'],
    ];

    expect($client?->getAttribute('name'))->toBe('A client')
        ->and($client->getAttribute('redirect_uris'))->toBe($retainedDocument['redirect_uris'])
        ->and($client->getAttribute('grant_types'))->toBe($retainedDocument['grant_types'])
        ->and($client->getAttribute('secret'))->toBeNull()
        ->and($metadata->getAttribute('client_id'))->toBe($client->getKey())
        ->and($metadata->getAttribute('registration_source'))->toBe('cimd')
        ->and($metadata->getAttribute('spec_revision'))->toBe(config('mcp-oauth.spec_revision'))
        ->and($metadata->getAttribute('token_endpoint_auth_method'))->toBe('none')
        ->and($metadata->getAttribute('client_id_issued_at')->getTimestamp())->toBe(now()->getTimestamp())
        ->and($metadata->getAttribute('metadata_document_url'))->toBe(CIMD_CLIENT_IDENTIFIER)
        ->and($metadata->getAttribute('metadata_document_url_sha256'))->toBe(hash('sha256', CIMD_CLIENT_IDENTIFIER))
        ->and($metadata->getAttribute('metadata_document_fetched_at')->getTimestamp())->toBe(now()->getTimestamp())
        ->and($metadata->getAttribute('metadata_document_expires_at')->getTimestamp())->toBe(now()->getTimestamp() + $retainedSeconds)
        ->and($metadata->getAttribute('metadata_document_status'))->toBe('valid')
        ->and($metadata->getAttribute('metadata_document_error'))->toBeNull()
        ->and($metadata->getAttribute('metadata_document'))->toEqual($shouldCache ? $retainedDocument : null)
        ->and($metadata->getAttribute('metadata_document_sha256'))->toBe($shouldCache ? hash('sha256', json_encode($retainedDocument, JSON_THROW_ON_ERROR)) : null)
        ->and($metadata->getAttribute('metadata_document_etag'))->toBe($shouldCache ? '"validator"' : null);

    $this->travel($retainedSeconds - 1)->seconds();
    expect($registry->resolve(CIMD_CLIENT_IDENTIFIER)?->getKey())->toBe($client->getKey());
})->with([
    'cache floor' => [0, true, 12],
    'origin freshness' => [20, true, 20],
    'cache ceiling' => [200, true, 30],
    'no-store' => [200, false, 12],
]);

it('applies the admission limit only to new metadata clients', function (): void {
    config()->set('mcp-oauth.cimd.enabled', true);
    config()->set('mcp-oauth.registrations_global_cap', 1);
    $existing = $this->createClient();
    identifyAsMetadataClient($existing, isExpired: true);
    $this->mock(ClientMetadataDocumentFetcherContract::class)->shouldReceive('fetch')->once()->with(CIMD_CLIENT_IDENTIFIER, null)
        ->andReturn(fetchedMetadata());
    $registry = app(ClientMetadataRegistryService::class);
    $newIdentifier = 'https://different-client.example/client.json';

    expect($registry->resolve($newIdentifier))->toBeNull()
        ->and(fn () => $registry->resolve($newIdentifier, canRegister: true))->toThrow(ClientMetadataUnavailableException::class)
        ->and($registry->resolve(CIMD_CLIENT_IDENTIFIER, canRegister: true)?->getKey())->toBe($existing->getKey())
        ->and(OAuthClientMetadata::query()->count())->toBe(1);
});

it('does not fetch or resolve a previously disabled CIMD client', function (bool $isPassportRevoked): void {
    config()->set('mcp-oauth.cimd.enabled', true);
    $client = $this->createClient(isRevoked: $isPassportRevoked);
    $metadata = identifyAsMetadataClient($client, isExpired: true);

    if (! $isPassportRevoked) {
        $metadata->update(['revoked_at' => now()]);
    }

    $this->mock(ClientMetadataDocumentFetcherContract::class)->shouldNotReceive('fetch');
    $registry = app(ClientMetadataRegistryService::class);

    expect($registry->resolve(CIMD_CLIENT_IDENTIFIER, canRegister: true))->toBeNull()
        ->and($registry->findForRevocation(CIMD_CLIENT_IDENTIFIER))->toBeNull();
})->with(['Passport client revoked' => true, 'OAuth metadata revoked' => false]);

it('rechecks a cached client against current host restrictions', function (string $blockedHost, bool $canRevoke): void {
    config()->set('mcp-oauth.cimd.enabled', true);
    $client = $this->createClient();
    identifyAsMetadataClient($client);
    OAuthBlockedRedirectHost::query()->create(['host' => $blockedHost, 'match_mode' => 'exact']);
    $this->mock(ClientMetadataDocumentFetcherContract::class)->shouldNotReceive('fetch');
    $registry = app(ClientMetadataRegistryService::class);

    expect($registry->resolve(CIMD_CLIENT_IDENTIFIER, canRegister: true))->toBeNull()
        ->and($registry->findForRevocation(CIMD_CLIENT_IDENTIFIER)?->getKey())->toBe($canRevoke ? $client->getKey() : null);
})->with(['metadata host' => ['client.example', false], 'callback host' => ['app.example', true]]);

it('does not recreate a client revoked while its document is fetched', function (): void {
    config()->set('mcp-oauth.cimd.enabled', true);
    $client = $this->createClient();
    $metadata = identifyAsMetadataClient($client, isExpired: true);
    $this->mock(ClientMetadataDocumentFetcherContract::class)->shouldReceive('fetch')->once()
        ->andReturnUsing(static function () use ($client): ClientMetadataDocumentData {
            $client->forceFill(['revoked' => true])->save();

            return fetchedMetadata();
        });
    $registry = app(ClientMetadataRegistryService::class);

    expect($registry->resolve(CIMD_CLIENT_IDENTIFIER, canRegister: true))->toBeNull()
        ->and(Passport::client()->newQuery()->count())->toBe(1)
        ->and(OAuthClientMetadata::query()->sole()->getKey())->toBe($metadata->getKey())
        ->and($client->refresh()->getAttribute('revoked'))->toBeTrue();
});

it('revalidates a cached document exactly at its deadline and preserves its validator on 304', function (int $firstAge, ?int $responseAge, ?string $missingTimestamp, int $remainingSeconds): void {
    config()->set('mcp-oauth.cimd.enabled', true);
    config()->set('mcp-oauth.cimd.cache_min_seconds', 12);
    $this->freezeSecond();
    $fetcher = $this->mock(ClientMetadataDocumentFetcherContract::class);
    $fetcher->shouldReceive('fetch')->once()->with(CIMD_CLIENT_IDENTIFIER, null)->andReturn(fetchedMetadata(maxAgeSeconds: $firstAge));
    $fetcher->shouldReceive('fetch')->once()->with(CIMD_CLIENT_IDENTIFIER, '"validator"')
        ->andReturn(new ClientMetadataDocumentData(ClientMetadataFetchStatusEnum::NotModified, maxAgeSeconds: $responseAge));
    $registry = app(ClientMetadataRegistryService::class);
    $registered = $registry->resolve(CIMD_CLIENT_IDENTIFIER, canRegister: true);
    $firstMetadata = OAuthClientMetadata::query()->sole();

    if ($missingTimestamp !== null) {
        $firstMetadata->update([$missingTimestamp => null]);
    }

    $this->travel($firstAge)->seconds();
    expect($registry->resolve(CIMD_CLIENT_IDENTIFIER)?->getKey())->toBe($registered?->getKey());
    $revalidatedMetadata = OAuthClientMetadata::query()->sole();

    expect($revalidatedMetadata->getAttribute('metadata_document'))->toBe($firstMetadata->getAttribute('metadata_document'))
        ->and($revalidatedMetadata->getAttribute('metadata_document_sha256'))->toBe($firstMetadata->getAttribute('metadata_document_sha256'))
        ->and($revalidatedMetadata->getAttribute('metadata_document_etag'))->toBe('"validator"')
        ->and($revalidatedMetadata->getAttribute('metadata_document_fetched_at')->getTimestamp())->toBe(now()->getTimestamp())
        ->and($revalidatedMetadata->getAttribute('metadata_document_expires_at')->getTimestamp())->toBe(now()->getTimestamp() + $remainingSeconds);
})->with([
    'minimum interval' => [12, null, null, 12],
    'inherits earlier freshness' => [70, null, null, 70],
    'explicit freshness replaces earlier value' => [70, 25, null, 25],
    'older record without fetched timestamp' => [70, null, 'metadata_document_fetched_at', 12],
    'older record without expiry timestamp' => [70, null, 'metadata_document_expires_at', 12],
]);

it('rejects a not-modified response without a complete cached entry', function (string $missingField): void {
    config()->set('mcp-oauth.cimd.enabled', true);
    $client = $this->createClient();
    $metadata = identifyAsMetadataClient($client, isExpired: true);
    $metadata->update([
        'metadata_document' => ['client_id' => CIMD_CLIENT_IDENTIFIER],
        'metadata_document_etag' => '"validator"',
        $missingField => null,
    ]);
    $this->mock(ClientMetadataDocumentFetcherContract::class)->shouldReceive('fetch')->once()
        ->andReturn(new ClientMetadataDocumentData(ClientMetadataFetchStatusEnum::NotModified));

    expect(app(ClientMetadataRegistryService::class)->resolve(CIMD_CLIENT_IDENTIFIER))->toBeNull()
        ->and($metadata->refresh()->getAttribute('metadata_document_status'))->toBe('invalid')
        ->and($metadata->getAttribute('metadata_document_error'))->toBe('invalid_document')
        ->and($metadata->getAttribute('metadata_document_etag'))->toBeNull()
        ->and($metadata->getAttribute('metadata_document_expires_at'))->toBeNull();
})->with(['metadata_document', 'metadata_document_etag']);

it('retries cached failures at the minimum interval', function (ClientMetadataFetchStatusEnum $failureStatus): void {
    config()->set('mcp-oauth.cimd.enabled', true);
    config()->set('mcp-oauth.cimd.cache_min_seconds', 12);
    $this->freezeSecond();
    $this->mock(ClientMetadataDocumentFetcherContract::class)->shouldReceive('fetch')->times(2)->with(CIMD_CLIENT_IDENTIFIER, null)
        ->andReturn(new ClientMetadataDocumentData($failureStatus), fetchedMetadata());
    $registry = app(ClientMetadataRegistryService::class);
    $resolve = fn (): ?Client => $registry->resolve(CIMD_CLIENT_IDENTIFIER, canRegister: true);

    for ($attempt = 0; $attempt < 2; $attempt++) {
        if ($failureStatus === ClientMetadataFetchStatusEnum::Unavailable) {
            expect($resolve)->toThrow(ClientMetadataUnavailableException::class);
        } else {
            expect($resolve())->toBeNull();
        }

        $this->travel($attempt === 0 ? 11 : 1)->seconds();
    }

    expect($resolve())->toBeInstanceOf(Client::class);
})->with([ClientMetadataFetchStatusEnum::Invalid, ClientMetadataFetchStatusEnum::Unavailable]);

it('reserves each in-flight identifier through the maximum fetch duration', function (): void {
    config()->set('mcp-oauth.cimd.enabled', true);
    config()->set('mcp-oauth.cimd.cache_min_seconds', 12);
    $this->freezeSecond();
    $fetcher = $this->mock(ClientMetadataDocumentFetcherContract::class);
    $registry = app(ClientMetadataRegistryService::class);
    $anotherIdentifier = 'https://another-client.example/client.json';
    $fetcher->shouldReceive('fetch')->once()->with($anotherIdentifier, null)
        ->andReturn(fetchedMetadata(['client_id' => $anotherIdentifier]));
    $fetcher->shouldReceive('fetch')->once()->with(CIMD_CLIENT_IDENTIFIER, null)
        ->andReturnUsing(function () use ($registry, $anotherIdentifier): ClientMetadataDocumentData {
            $this->travel(30)->seconds();
            $retryKey = 'mcp-oauth:cimd:'.hash('sha256', CIMD_CLIENT_IDENTIFIER);

            expect(fn () => $registry->resolve(CIMD_CLIENT_IDENTIFIER, canRegister: true))->toThrow(ClientMetadataUnavailableException::class)
                ->and($registry->resolve($anotherIdentifier, canRegister: true))->toBeInstanceOf(Client::class)
                ->and(Cache::get($retryKey))->toBe(ClientMetadataFetchStatusEnum::Unavailable->value);

            $this->travel(1)->seconds();
            expect(Cache::has($retryKey))->toBeFalse();

            return fetchedMetadata();
        });

    expect($registry->resolve(CIMD_CLIENT_IDENTIFIER, canRegister: true))->toBeInstanceOf(Client::class)
        ->and(OAuthClientMetadata::query()->count())->toBe(2);
});

it('does not reuse outbound metadata when a companion definition claims the identifier during a fetch', function (): void {
    config()->set('mcp-oauth.cimd.enabled', true);
    $client = $this->createClient();
    $metadata = identifyAsMetadataClient($client, isExpired: true);
    $this->mock(ClientMetadataDocumentFetcherContract::class)->shouldReceive('fetch')->once()
        ->andReturnUsing(static function () use ($metadata): ClientMetadataDocumentData {
            $metadata->update([
                'registration_source' => 'companion',
                'metadata_document_expires_at' => now()->addMinute(),
            ]);

            return fetchedMetadata(['client_name' => 'Untrusted response']);
        });

    expect(app(ClientMetadataRegistryService::class)->resolve(CIMD_CLIENT_IDENTIFIER))->toBeNull()
        ->and($metadata->refresh()->getAttribute('registration_source'))->toBe('companion')
        ->and($client->fresh()->getAttribute('name'))->toBe($client->getAttribute('name'));
});

it('keeps the registration another request updated during a fetch', function (bool $isWinnerFresh): void {
    config()->set('mcp-oauth.cimd.enabled', true);
    $client = $this->createClient();
    $metadata = identifyAsMetadataClient($client, isExpired: true);
    $fetcher = $this->mock(ClientMetadataDocumentFetcherContract::class);
    $fetcher->shouldReceive('fetch')->once()->with(CIMD_CLIENT_IDENTIFIER, null)
        ->andReturnUsing(static function () use ($metadata, $isWinnerFresh): ClientMetadataDocumentData {
            $metadata->update([
                'metadata_document_status' => $isWinnerFresh ? 'valid' : 'invalid',
                'metadata_document_etag' => '"winner"',
                'metadata_document_expires_at' => $isWinnerFresh ? now()->addMinute() : null,
            ]);

            return $isWinnerFresh
                ? new ClientMetadataDocumentData(ClientMetadataFetchStatusEnum::Invalid)
                : fetchedMetadata(['client_name' => 'Later response']);
        });
    $resolved = app(ClientMetadataRegistryService::class)->resolve(CIMD_CLIENT_IDENTIFIER);

    expect($resolved?->getKey())->toBe($isWinnerFresh ? $client->getKey() : null)
        ->and($metadata->fresh()->getAttribute('metadata_document_etag'))->toBe('"winner"')
        ->and($client->fresh()->getAttribute('name'))->toBe($client->getAttribute('name'));
})->with(['updated registration' => true, 'invalidated registration' => false]);

it('reuses the winning registration after a conflicting first insert only while it is fresh', function (?bool $isWinnerFresh): void {
    config()->set('mcp-oauth.cimd.enabled', true);
    $this->mock(ClientMetadataDocumentFetcherContract::class)->shouldReceive('fetch')->once()->andReturn(fetchedMetadata());
    $collision = new UniqueConstraintViolationException('fixture', 'insert into oauth_client_metadata', [], new RuntimeException('Duplicate registration'));
    $this->mock(ClientRepository::class)->shouldReceive('createAuthorizationCodeGrantClient')->once()->andThrow($collision);
    $winningClient = null;

    if ($isWinnerFresh !== null) {
        // Publish the other request's row after the failed transaction releases its locks.
        Event::listen(TransactionRolledBack::class, function () use ($isWinnerFresh, &$winningClient): void {
            $winningClient = $this->createClient();
            identifyAsMetadataClient($winningClient, isExpired: ! $isWinnerFresh);
        });
    }

    $resolve = fn (): ?Client => app(ClientMetadataRegistryService::class)->resolve(CIMD_CLIENT_IDENTIFIER, canRegister: true);

    if ($isWinnerFresh === null) {
        expect($resolve)->toThrow(UniqueConstraintViolationException::class, 'Duplicate registration');

        return;
    }

    $resolved = $resolve();
    expect($winningClient)->toBeInstanceOf(Client::class)
        ->and($resolved?->getKey())->toBe($isWinnerFresh ? $winningClient->getKey() : null)
        ->and(OAuthClientMetadata::query()->count())->toBe(1);
})->with(['fresh winner' => [true], 'expired winner' => [false], 'no winner' => [null]]);

it('enforces the redirect URI policy on fetched metadata', function (string $redirectUri, array $domains, bool $isAllowed): void {
    config()->set('mcp-oauth.cimd.enabled', true);
    config()->set('mcp.redirect_domains', $domains);
    config()->set('mcp.custom_schemes', ['cursor']);
    OAuthBlockedRedirectHost::query()->create(['host' => 'blocked.example', 'match_mode' => 'exact']);
    $this->mock(ClientMetadataDocumentFetcherContract::class)->shouldReceive('fetch')->once()
        ->andReturn(fetchedMetadata(['redirect_uris' => [$redirectUri]]));

    $resolved = app(ClientMetadataRegistryService::class)->resolve(CIMD_CLIENT_IDENTIFIER, canRegister: true);

    expect($resolved?->getAttribute('redirect_uris'))->toBe($isAllowed ? [$redirectUri] : null);
})->with([
    'exact byte ceiling' => ['https://app.example/'.str_repeat('p', 1004), ['https://app.example/'], true],
    'exceeds byte ceiling' => ['https://app.example/'.str_repeat('p', 1005), ['*'], false],
    'blocked host despite wildcard' => ['https://blocked.example/callback', ['*'], false],
    'different domain' => ['https://app.example.other/callback', ['https://app.example'], false],
    'configured native scheme' => ['cursor://anysphere.cursor-retrieval/oauth/callback', ['https://app.example'], true],
    'IPv4 with localhost policy' => ['http://127.0.0.1:31415/callback', ['http://localhost'], true],
    'IPv4 with IPv6 loopback policy' => ['http://127.0.0.1:31415/callback', ['http://[::1]'], true],
    'IPv6 with IPv4 loopback policy' => ['http://[::1]:31415/callback', ['http://127.0.0.1/'], true],
    'loopback with unrelated policy' => ['http://127.0.0.1:31415/callback', ['https://app.example'], false],
    'loopback allowed by wildcard' => ['http://[::1]:31415/callback', ['*'], true],
    'insecure non-loopback' => ['http://app.example/callback', ['*'], false],
]);

it('uses the document host when its supplied display name is unsuitable', function (mixed $clientName, string $expectedName): void {
    config()->set('mcp-oauth.cimd.enabled', true);
    $this->mock(ClientMetadataDocumentFetcherContract::class)->shouldReceive('fetch')->once()
        ->andReturn(fetchedMetadata(['client_name' => $clientName, 'redirect_uris' => array_fill(0, 10, AuthorizeFlowTestCase::REGISTERED_REDIRECT_URI)]));

    $resolved = app(ClientMetadataRegistryService::class)->resolve(CIMD_CLIENT_IDENTIFIER, canRegister: true);

    expect($resolved?->getAttribute('name'))->toBe($expectedName);
})->with([
    'integer' => [1024, 'client.example'],
    'empty' => ['', 'client.example'],
    'only spaces' => [' ', 'client.example'],
    'control character' => ["Example\nclient", 'client.example'],
    'name at limit' => [str_repeat('n', 255), str_repeat('n', 255)],
    'too long' => [str_repeat('n', 256), 'client.example'],
]);

it('revokes issued tokens when the refreshed callback policy changes or becomes invalid', function (string $fetchStatus): void {
    config()->set('mcp-oauth.cimd.enabled', true);
    $client = $this->createClient();
    ['code' => $code] = $this->obtainAuthorizationCode($client);
    $tokens = $this->post('/oauth/token', $this->codeExchange($client, $code))->assertOk();

    $metadata = identifyAsMetadataClient($client, isExpired: true);
    $bearerRequest = Request::create('/mcp', server: ['HTTP_AUTHORIZATION' => 'Bearer '.$tokens->json('access_token')]);
    $authenticator = app(AccessTokenAuthenticator::class);
    $fetcher = $this->mock(ClientMetadataDocumentFetcherContract::class);
    $fetcher->shouldReceive('fetch')->once()->andReturn(new ClientMetadataDocumentData(ClientMetadataFetchStatusEnum::from($fetchStatus), [
        'client_id' => CIMD_CLIENT_IDENTIFIER,
        'redirect_uris' => ['https://app.example/changed-callback'],
        'grant_types' => ['authorization_code', 'refresh_token'],
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

it('revokes the previous credentials when refreshed metadata removes the refresh grant', function (): void {
    config()->set('mcp-oauth.cimd.enabled', true);
    $client = $this->createClient();
    ['code' => $code] = $this->obtainAuthorizationCode($client);
    $this->post('/oauth/token', $this->codeExchange($client, $code))->assertOk();
    identifyAsMetadataClient($client, isExpired: true);
    $this->mock(ClientMetadataDocumentFetcherContract::class)->shouldReceive('fetch')->once()
        ->andReturn(fetchedMetadata(['grant_types' => ['authorization_code']]));

    $revalidated = app(ClientMetadataRegistryService::class)->resolve(CIMD_CLIENT_IDENTIFIER);

    expect($revalidated?->getKey())->toBe($client->getKey())
        ->and($revalidated->getAttribute('grant_types'))->toBe(['authorization_code'])
        ->and(Passport::token()->newQuery()->sole()->getAttribute('revoked'))->toBeTrue()
        ->and(Passport::refreshToken()->newQuery()->sole()->getAttribute('revoked'))->toBeTrue();
});

it('refuses client authentication before processing a public metadata client code', function (string $unsupportedParameter): void {
    config()->set('mcp-oauth.cimd.enabled', true);
    $this->mock(ClientMetadataDocumentFetcherContract::class)->shouldNotReceive('fetch');
    $client = $this->createClient();
    ['code' => $code] = $this->obtainAuthorizationCode($client);
    identifyAsMetadataClient($client);
    $exchange = $this->codeExchange($client, $code, ['client_id' => CIMD_CLIENT_IDENTIFIER]);

    $this->post('/oauth/token', [...$exchange, $unsupportedParameter => 'unsupported'])
        ->assertUnauthorized()->assertJsonPath('error', 'invalid_client');
    $this->post('/oauth/token', $exchange)->assertOk();
})->with(['client_secret', 'client_assertion', 'client_assertion_type']);

it('rejects a grant type outside the protocol before checking its resource', function (): void {
    $this->post('/oauth/token', ['grant_type' => 'client_credentials'])
        ->assertBadRequest()->assertJsonPath('error', 'unsupported_grant_type');
});

it('returns 503 at the token endpoint while a known metadata client is unavailable', function (): void {
    config()->set('mcp-oauth.cimd.enabled', true);
    $client = $this->createClient();
    identifyAsMetadataClient($client, isExpired: true);
    $this->mock(ClientMetadataDocumentFetcherContract::class)->shouldReceive('fetch')->once()
        ->andReturn(new ClientMetadataDocumentData(ClientMetadataFetchStatusEnum::Unavailable));

    $this->post('/oauth/token', [
        'client_id' => CIMD_CLIENT_IDENTIFIER,
        'grant_type' => 'refresh_token',
        'refresh_token' => 'test-refresh-token',
        'resource' => AuthorizeFlowTestCase::RESOURCE,
    ])->assertServiceUnavailable()->assertJsonPath('error', 'temporarily_unavailable');
});

it('refuses a code exchange against a callback absent from the current document registration', function (): void {
    config()->set('mcp-oauth.cimd.enabled', true);
    $this->mock(ClientMetadataDocumentFetcherContract::class)->shouldNotReceive('fetch');
    $client = $this->createClient();
    ['code' => $code] = $this->obtainAuthorizationCode($client);
    identifyAsMetadataClient($client);
    $client->forceFill(['redirect_uris' => ['https://app.example/new-callback']])->save();

    $this->post('/oauth/token', $this->codeExchange($client, $code, ['client_id' => CIMD_CLIENT_IDENTIFIER]))
        ->assertBadRequest()->assertJsonPath('error', 'invalid_grant');
    expect(Passport::token()->newQuery()->exists())->toBeFalse();
});
