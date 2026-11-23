<?php

declare(strict_types=1);

use Illuminate\Cache\RateLimiting\Limit;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Support\Str;
use Illuminate\Validation\ValidationException;
use Laravel\Passport\Bridge\User;
use Laravel\Passport\Client;
use Laravel\Passport\Passport;
use League\OAuth2\Server\RequestTypes\AuthorizationRequest;
use League\Uri\UriString;
use Qiick\McpOAuth\Contracts\ConsentProvider;
use Qiick\McpOAuth\Data\ConsentDecision;
use Qiick\McpOAuth\Data\ConsentOption;
use Qiick\McpOAuth\Data\ConsentOptions;
use Qiick\McpOAuth\Events\McpConsentApproved;
use Qiick\McpOAuth\Events\McpConsentDenied;
use Qiick\McpOAuth\McpOAuthRoutes;
use Qiick\McpOAuth\Models\OAuthBlockedRedirectHost;
use Qiick\McpOAuth\Models\OAuthClientMetadata;
use Qiick\McpOAuth\Models\OAuthConsentRecord;
use Qiick\McpOAuth\Testing\FakeConsentProvider;
use Qiick\McpOAuth\Tests\Support\AuthorizeFlowTestCase;
use Qiick\McpOAuth\Tests\Support\ForeignAuthorizationRequest;
use Qiick\McpOAuth\Tests\Support\SkippingAuthorizationClient;
use Qiick\McpOAuth\Tests\Support\TestUser;

uses(AuthorizeFlowTestCase::class);

const INERTIA_HEADERS = ['X-Inertia' => 'true', 'Accept' => 'text/html, application/xhtml+xml'];

beforeEach(function (): void {
    RateLimiter::clear('authorize');
});

/**
 * Signs the user in, renders the consent page through the default Inertia
 * view and returns its props (the pending request now sits in the session).
 *
 * @param  array<string, mixed>  $queryOverrides
 * @return array<string, mixed>
 */
function renderConsentPage(AuthorizeFlowTestCase $testCase, TestUser $user, Client $client, array $queryOverrides = []): array
{
    $response = $testCase->actingAs($user)
        ->get(authorizeUrlFor($testCase, $client, $queryOverrides), INERTIA_HEADERS);

    $response->assertOk()->assertJsonPath('component', 'oauth/authorize');

    /** @var array<string, mixed> $props */
    $props = $response->json('props');

    return $props;
}

/**
 * @param  array<string, mixed>  $overrides
 */
function authorizeUrlFor(AuthorizeFlowTestCase $testCase, Client $client, array $overrides = []): string
{
    $reflection = new ReflectionMethod($testCase, 'authorizeUrl');

    return $reflection->invoke($testCase, $client, $overrides);
}

/**
 * @return array<string, mixed>
 */
function validApproval(string $authToken, array $overrides = []): array
{
    // A null override removes the field, as a form that never sent it.
    return array_filter(array_merge([
        'auth_token' => $authToken,
        'scopes' => ['mcp:read'],
        'role' => 'editor',
        'resources' => ['news'],
        'all_resources' => false,
    ], $overrides), static fn (mixed $value): bool => $value !== null);
}

/**
 * @return array<string, string>
 */
function queryOfLocation(string $location): array
{
    $query = (string) UriString::parse($location)['query'];
    parse_str($query, $parameters);

    /** @var array<string, string> $parameters */
    return $parameters;
}

// --- Off gate (design §4.2) --------------------------------------------------

it('with OAuth off matches an unregistered /oauth/authorize on every method', function (string $method, string $accept): void {
    config()->set('app.debug', false);
    config()->set('mcp-oauth.enabled', false);
    $server = ['HTTP_ACCEPT' => $accept];

    $unregisteredResponse = $this->call($method, '/oauth/authorize?client_id=x', server: $server);

    McpOAuthRoutes::register();

    $gatedResponse = $this->call($method, '/oauth/authorize?client_id=x', server: $server);

    expect($gatedResponse->getStatusCode())->toBe(404)
        ->and($gatedResponse->getStatusCode())->toBe($unregisteredResponse->getStatusCode())
        ->and($gatedResponse->headers->get('Allow'))->toBe($unregisteredResponse->headers->get('Allow'))
        ->and($gatedResponse->headers->get('X-Frame-Options'))->toBeNull()
        ->and($gatedResponse->headers->has('Set-Cookie'))->toBe($unregisteredResponse->headers->has('Set-Cookie'));

    if ($method !== 'HEAD') {
        expect($gatedResponse->getContent())->toBe($unregisteredResponse->getContent())
            ->and($gatedResponse->headers->get('Content-Type'))->toBe($unregisteredResponse->headers->get('Content-Type'));
    }
})->with(['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'])
    ->with(['application/json', 'text/html']);

it('answers 405 with the allowed methods when OAuth is on', function (string $method): void {
    $this->enableOAuth();
    McpOAuthRoutes::register();

    $this->call($method, '/oauth/authorize')
        ->assertStatus(405)
        ->assertHeader('Allow', 'GET, HEAD, POST, DELETE');
})->with(['PUT', 'PATCH', 'OPTIONS']);

it('answers a browser 503 page and a JSON 503 when Passport keys are missing', function (): void {
    $this->enableOAuth();
    config()->set('passport.private_key', '');
    config()->set('passport.public_key', '');
    $missingKeyDirectory = sys_get_temp_dir().'/mcp-oauth-authorize-no-keys-'.uniqid('', true);
    mkdir($missingKeyDirectory, 0700);
    Passport::loadKeysFrom($missingKeyDirectory);
    McpOAuthRoutes::register();
    $client = $this->createClient();

    $browserResponse = $this->get($this->authorizeUrl($client), ['Accept' => 'text/html']);

    $browserResponse->assertStatus(503);
    expect($browserResponse->headers->get('Content-Type'))->toStartWith('text/html')
        ->and($browserResponse->getContent())->toContain('temporarily unavailable');

    $this->getJson($this->authorizeUrl($client))
        ->assertStatus(503)
        ->assertJsonPath('error', 'temporarily_unavailable');
});

// --- Authorization request checks: JSON, never a redirect (RFC 6749 §4.1.2.1)

it('refuses an authorization request without PKCE S256 as JSON, never a redirect', function (array $overrides, string $error): void {
    $this->enableOAuth();
    McpOAuthRoutes::register();
    $client = $this->createClient();

    $response = $this->actingAs($this->createUser())->get($this->authorizeUrl($client, $overrides));

    $response->assertStatus(400)
        ->assertHeaderMissing('Location')
        ->assertJsonPath('error', $error);

    expect(session()->has('authRequest'))->toBeFalse();
})->with([
    'plain method' => [['code_challenge_method' => 'plain'], 'invalid_request'],
    'missing method' => [['code_challenge_method' => null], 'invalid_request'],
    'lower-case method' => [['code_challenge_method' => 's256'], 'invalid_request'],
    'missing challenge' => [['code_challenge' => null], 'invalid_request'],
    'empty challenge' => [['code_challenge' => ''], 'invalid_request'],
    'implicit response type' => [['response_type' => 'token'], 'unsupported_response_type'],
    'missing response type' => [['response_type' => null], 'unsupported_response_type'],
    'missing resource' => [['resource' => null], 'invalid_target'],
    'other resource' => [['resource' => 'https://evil.example/mcp'], 'invalid_target'],
    'resource prefix' => [['resource' => 'https://mcp-oauth.test/mc'], 'invalid_target'],
    'array state' => [['state' => ['a', 'b']], 'invalid_request'],
    'array redirect uri' => [['redirect_uri' => [AuthorizeFlowTestCase::REGISTERED_REDIRECT_URI]], 'invalid_request'],
    'array challenge' => [['code_challenge' => [AuthorizeFlowTestCase::CODE_CHALLENGE]], 'invalid_request'],
    'array challenge method' => [['code_challenge_method' => ['S256']], 'invalid_request'],
    'array response type' => [['response_type' => ['code']], 'unsupported_response_type'],
    'array client id' => [['client_id' => ['x']], 'invalid_client'],
]);

it('names the failed check in error_description', function (array $overrides, string $description): void {
    $this->enableOAuth();
    McpOAuthRoutes::register();
    $client = $this->createClient();

    $this->actingAs($this->createUser())
        ->get($this->authorizeUrl($client, $overrides))
        ->assertStatus(400)
        ->assertJsonPath('error_description', $description);
})->with([
    'pkce' => [['code_challenge_method' => 'plain'], 'PKCE with code_challenge_method S256 is required.'],
    'response type' => [['response_type' => 'token'], 'Only response_type=code is supported.'],
    'resource' => [['resource' => null], 'The resource parameter is required and must name this MCP endpoint.'],
    'client' => [['client_id' => 'not-a-uuid'], 'The client is unknown, revoked or blocked on this server.'],
    'redirect' => [['redirect_uri' => 'https://evil.example/cb'], 'The redirect_uri is not registered for this client.'],
]);

it('never queries the clients table for a client_id that is not a UUID', function (): void {
    $this->enableOAuth();
    McpOAuthRoutes::register();
    $client = $this->createClient();
    DB::enableQueryLog();

    $this->actingAs($this->createUser())
        ->get($this->authorizeUrl($client, ['client_id' => 'not-a-uuid']))
        ->assertStatus(400);

    $clientQueries = array_filter(DB::getQueryLog(), static fn (array $query): bool => str_contains($query['query'], 'oauth_clients'));

    expect($clientQueries)->toBe([]);
});

it('refuses unknown, malformed and revoked clients as JSON', function (string $clientId): void {
    $this->enableOAuth();
    McpOAuthRoutes::register();
    $revokedClient = $this->createClient(isRevoked: true);
    $clientId = $clientId === 'revoked' ? (string) $revokedClient->getKey() : $clientId;

    $this->actingAs($this->createUser())
        ->get('/oauth/authorize?'.http_build_query(array_merge(
            $this->authorizeQuery($revokedClient),
            ['client_id' => $clientId],
        )))
        ->assertStatus(400)
        ->assertHeaderMissing('Location')
        ->assertJsonPath('error', 'invalid_client');
})->with([
    'unknown uuid' => ['0193b6a4-7a1e-7000-8000-000000000000'],
    'not a uuid' => ['not-a-uuid'],
    'empty' => [''],
    'revoked' => ['revoked'],
]);

it('refuses as JSON a Passport client the package did not register', function (): void {
    $this->enableOAuth();
    McpOAuthRoutes::register();
    $client = $this->createClient();
    // A product's own authorization_code client, or a client from before DCR wrote its row.
    OAuthClientMetadata::query()->where('client_id', $client->getKey())->delete();

    $this->actingAs($this->createUser())
        ->get($this->authorizeUrl($client))
        ->assertStatus(400)
        ->assertHeaderMissing('Location')
        ->assertJsonPath('error', 'invalid_client');
});

it('refuses a client with a blocked redirect host as JSON', function (): void {
    $this->enableOAuth();
    McpOAuthRoutes::register();
    $client = $this->createClient();
    OAuthBlockedRedirectHost::query()->create(['host' => 'app.example', 'match_mode' => 'host_and_subdomains']);

    $this->actingAs($this->createUser())
        ->get($this->authorizeUrl($client))
        ->assertStatus(400)
        ->assertHeaderMissing('Location')
        ->assertJsonPath('error', 'invalid_client');
});

it('never redirects to a redirect_uri that is not exactly registered', function (string $redirectUri, array $registeredUris): void {
    $this->enableOAuth();
    McpOAuthRoutes::register();
    $client = $this->createClient($registeredUris);

    // prompt=none would make league redirect an error to the redirect URI.
    $response = $this->get($this->authorizeUrl($client, ['redirect_uri' => $redirectUri, 'prompt' => 'none']));

    $response->assertStatus(400)
        ->assertHeaderMissing('Location')
        ->assertJsonPath('error', 'invalid_request');
})->with([
    'other host' => ['https://evil.example/callback', ['https://app.example/callback']],
    'other path' => ['https://app.example/other', ['https://app.example/callback']],
    'trailing slash' => ['https://app.example/callback/', ['https://app.example/callback']],
    'extra query' => ['https://app.example/callback?next=evil', ['https://app.example/callback']],
    'other port' => ['https://app.example:8443/callback', ['https://app.example/callback']],
    'loopback with another port' => ['http://127.0.0.1:9999/callback', ['http://127.0.0.1:8080/callback']],
    'ipv6 loopback with another port' => ['http://[::1]:9999/callback', ['http://[::1]:8080/callback']],
    'fragment' => ['https://app.example/callback#x', ['https://app.example/callback']],
    'http instead of https' => ['http://app.example/callback', ['https://app.example/callback']],
    'missing with two registered' => ['', ['https://app.example/a', 'https://app.example/b']],
]);

it('drops foreign wire scopes before Passport sees them', function (string|array $scope): void {
    $this->enableOAuth();
    McpOAuthRoutes::register();
    $client = $this->createClient();

    renderConsentPage($this, $this->createUser(), $client, ['scope' => $scope]);

    $pendingRequest = unserialize((string) session('authRequest'));
    $scopeIdentifiers = array_map(
        static fn ($bridgeScope): string => $bridgeScope->getIdentifier(),
        $pendingRequest->getScopes(),
    );

    expect($scopeIdentifiers)->toBe(['mcp:use']);
})->with([
    'foreign scopes around the wire scope' => ['openid mcp:use admin'],
    'only foreign scopes' => ['openid profile'],
    'empty scope' => [''],
    'repeated scope parameter' => [['mcp:use', 'admin']],
]);

// --- Login and the consent page ----------------------------------------------

it('sends a guest to the login page and keeps the full authorize URL as intended', function (): void {
    $this->enableOAuth();
    McpOAuthRoutes::register();
    $client = $this->createClient();
    $authorizeUrl = $this->authorizeUrl($client);

    $this->get($authorizeUrl)->assertRedirect('/login');

    $intendedUrl = (string) session('url.intended');

    expect($intendedUrl)->toStartWith(url('/oauth/authorize').'?')
        ->and(queryOfLocation($intendedUrl))->toEqualCanonicalizing($this->authorizeQuery($client));
});

it('renders the consent page with the client as self-asserted, the return host and the options', function (): void {
    $consentProvider = $this->enableOAuth();
    McpOAuthRoutes::register();
    $client = $this->createClient(['https://app.example/callback', 'https://other.example/cb']);

    $response = $this->actingAs($this->createUser())
        ->get($this->authorizeUrl($client), INERTIA_HEADERS);

    $response->assertOk()
        ->assertHeader('X-Frame-Options', 'DENY')
        ->assertJsonPath('component', 'oauth/authorize')
        ->assertJsonPath('props.client.id', (string) $client->getKey())
        ->assertJsonPath('props.client.name', 'Cursor')
        ->assertJsonPath('props.client.redirectHost', 'app.example')
        ->assertJsonPath('props.client.nameIsSelfAsserted', true)
        ->assertJsonPath('props.authToken', session('authToken'))
        ->assertJsonPath('props.options.scopes.0', ['value' => 'mcp:read', 'label' => 'Read through MCP', 'grantable' => true, 'description' => null])
        ->assertJsonPath('props.options.scopes.2.grantable', false)
        ->assertJsonPath('props.options.roles.0.value', 'editor')
        ->assertJsonPath('props.options.resources.1.value', 'events')
        ->assertJsonPath('props.options.organisations', [])
        ->assertJsonPath('props.options.resourcesRequired', true)
        ->assertJsonPath('props.options.canGrant', true)
        ->assertJsonPath('props.options.notices', []);

    expect($response->headers->all('content-security-policy'))->toContain("frame-ancestors 'none'")
        ->and($consentProvider->askedClients[0]->redirectUris)->toBe(['https://app.example/callback', 'https://other.example/cb'])
        ->and($consentProvider->askedClients[0]->redirectHost)->toBe('app.example');
});

it('shows the only registered host when the request omits redirect_uri', function (): void {
    $this->enableOAuth();
    McpOAuthRoutes::register();
    $client = $this->createClient(['https://solo.example/cb']);

    $props = renderConsentPage($this, $this->createUser(), $client, ['redirect_uri' => null]);

    expect($props['client']['redirectHost'])->toBe('solo.example');
});

it('asks for consent every time, even right after an approval', function (): void {
    $this->enableOAuth();
    McpOAuthRoutes::register();
    $client = $this->createClient();
    $user = $this->createUser();

    $props = renderConsentPage($this, $user, $client);
    $this->post('/oauth/authorize', validApproval($props['authToken']))->assertRedirect();

    renderConsentPage($this, $user, $client);
});

it('answers prompt=none with consent_required on the registered URI, keeping state and adding iss', function (): void {
    $this->enableOAuth();
    McpOAuthRoutes::register();
    $client = $this->createClient();

    $response = $this->actingAs($this->createUser())->get($this->authorizeUrl($client, ['prompt' => 'none']));

    $location = (string) $response->headers->get('Location');
    $parameters = queryOfLocation($location);

    expect($location)->toStartWith(AuthorizeFlowTestCase::REGISTERED_REDIRECT_URI.'?')
        ->and($parameters['error'])->toBe('consent_required')
        ->and($parameters['state'])->toBe('state-1234')
        ->and($parameters['iss'])->toBe('https://mcp-oauth.test');
});

it('throttles the authorization endpoint with mcp-oauth-authorize', function (): void {
    $this->enableOAuth();
    McpOAuthRoutes::register();
    $client = $this->createClient();
    RateLimiter::for('mcp-oauth-authorize', static fn (Request $request): Limit => Limit::perMinute(2)->by('authorize'));

    $this->get($this->authorizeUrl($client))->assertRedirect('/login');
    $this->get($this->authorizeUrl($client))->assertRedirect('/login');
    $this->get($this->authorizeUrl($client))->assertStatus(429);
});

// --- Approve -----------------------------------------------------------------

it('approves: narrowed grant, consent record, event, then the code with state and iss', function (): void {
    Event::fake([McpConsentApproved::class]);
    $this->enableOAuth();
    McpOAuthRoutes::register();
    $client = $this->createClient();
    $user = $this->createUser();
    $props = renderConsentPage($this, $user, $client, ['scope' => 'openid mcp:use']);

    $response = $this->post('/oauth/authorize', validApproval($props['authToken'], [
        'scopes' => ['mcp:read', 'mcp:write'],
        'resources' => ['news', 'events'],
    ]), ['User-Agent' => 'ConsentTest/1.0']);

    $location = (string) $response->headers->get('Location');
    $parameters = queryOfLocation($location);

    expect($response->getStatusCode())->toBe(302)
        ->and($location)->toStartWith(AuthorizeFlowTestCase::REGISTERED_REDIRECT_URI.'?')
        ->and($parameters['code'])->not->toBe('')
        ->and($parameters['state'])->toBe('state-1234')
        ->and($parameters['iss'])->toBe('https://mcp-oauth.test')
        ->and(session()->has('authRequest'))->toBeFalse()
        ->and(session()->has('authToken'))->toBeFalse();

    $decision = $this->grantStore()->replacedDecisions[0];
    $grant = $this->grantStore()->activeFor((string) $client->getKey(), (string) $user->getKey());

    expect($decision)->toEqual(new ConsentDecision(
        clientId: (string) $client->getKey(),
        userIdentifier: (string) $user->getKey(),
        redirectUri: AuthorizeFlowTestCase::REGISTERED_REDIRECT_URI,
        scopes: ['mcp:read', 'mcp:write'],
        role: 'editor',
        resources: ['news', 'events'],
        allResources: false,
    ))->and($grant)->not->toBeNull();

    $authCode = DB::table('oauth_auth_codes')->sole();

    expect(json_decode((string) $authCode->scopes, true))->toBe(['mcp:use'])
        ->and((string) $authCode->user_id)->toBe((string) $user->getKey());

    $consentRecord = OAuthConsentRecord::query()->sole();

    expect($consentRecord->decision)->toBe('approved')
        ->and($consentRecord->client_id)->toBe((string) $client->getKey())
        ->and($consentRecord->user_identifier)->toBe((string) $user->getKey())
        ->and($consentRecord->grant_id)->toBe($grant->id)
        ->and($consentRecord->redirect_uri)->toBe(AuthorizeFlowTestCase::REGISTERED_REDIRECT_URI)
        ->and($consentRecord->redirect_host)->toBe('app.example')
        ->and($consentRecord->resource)->toBe('https://mcp-oauth.test/mcp')
        ->and($consentRecord->requested_scopes)->toBe(['mcp:use'])
        ->and($consentRecord->granted_scopes)->toBe(['mcp:read', 'mcp:write'])
        ->and($consentRecord->role)->toBe('editor')
        ->and($consentRecord->resources)->toBe(['news', 'events'])
        ->and($consentRecord->all_resources)->toBeFalse()
        ->and($consentRecord->attributes)->toBe([])
        ->and($consentRecord->locale)->toBe('en')
        ->and($consentRecord->ip_address)->toBe('127.0.0.1')
        ->and($consentRecord->user_agent)->toBe('ConsentTest/1.0')
        ->and($consentRecord->retention_until)->toBeNull();

    Event::assertDispatched(McpConsentApproved::class, static function (McpConsentApproved $event) use ($client, $user, $grant): bool {
        return $event->clientId === (string) $client->getKey()
            && $event->userIdentifier === (string) $user->getKey()
            && $event->grantId === $grant->id
            && $event->redirectHost === 'app.example'
            && $event->scopes === ['mcp:read', 'mcp:write']
            && $event->resources === ['news', 'events'];
    });
});

it('approves with every resource only when the user says so explicitly', function (): void {
    $this->enableOAuth();
    McpOAuthRoutes::register();
    $client = $this->createClient();
    $props = renderConsentPage($this, $this->createUser(), $client);

    $this->post('/oauth/authorize', validApproval($props['authToken'], [
        'resources' => ['news'],
        'all_resources' => true,
    ]))->assertRedirect();

    $decision = $this->grantStore()->replacedDecisions[0];

    expect($decision->allResources)->toBeTrue()
        ->and($decision->resources)->toBe([])
        ->and(OAuthConsentRecord::query()->sole()->all_resources)->toBeTrue();
});

it('leaves an Inertia approval with a full-page location to the client', function (): void {
    $this->enableOAuth();
    McpOAuthRoutes::register();
    $client = $this->createClient();
    $props = renderConsentPage($this, $this->createUser(), $client);

    $response = $this->post('/oauth/authorize', validApproval($props['authToken']), INERTIA_HEADERS);

    $response->assertStatus(409);
    expect((string) $response->headers->get('X-Inertia-Location'))->toStartWith(AuthorizeFlowTestCase::REGISTERED_REDIRECT_URI.'?code=');
});

it('refuses an approval without the pending request it was rendered for', function (string $case): void {
    $this->enableOAuth();
    McpOAuthRoutes::register();
    $client = $this->createClient();
    $user = $this->createUser();
    $props = renderConsentPage($this, $user, $client);
    $authToken = $props['authToken'];

    if ($case === 'no pending request') {
        session()->forget(['authToken', 'authRequest']);
    }

    if ($case === 'wrong auth token') {
        $authToken = 'not-the-token';
    }

    if ($case === 'missing auth token') {
        $authToken = null;
    }

    if ($case === 'another user') {
        $this->actingAs($this->createUser());
    }

    if ($case === 'client revoked since') {
        $client->forceFill(['revoked' => true])->save();
    }

    if ($case === 'redirect host blocked since') {
        OAuthBlockedRedirectHost::query()->create(['host' => 'app.example', 'match_mode' => 'host_and_subdomains']);
    }

    if ($case === 'corrupt pending request') {
        session()->put('authRequest', serialize(new ArrayObject));
    }

    if ($case === 'pending request of a class outside the allowlist') {
        // Everything else is right: only the unserialize allowlist refuses it.
        $foreignRequest = new ForeignAuthorizationRequest;
        $foreignRequest->setUser(new User((string) $user->getKey()));
        $foreignRequest->setClient(new Laravel\Passport\Bridge\Client((string) $client->getKey(), 'Cursor', [AuthorizeFlowTestCase::REGISTERED_REDIRECT_URI]));
        $foreignRequest->setGrantTypeId('authorization_code');
        session()->put('authRequest', serialize($foreignRequest));
    }

    if ($case === 'pending request without a user') {
        session()->put('authRequest', serialize(new AuthorizationRequest));
    }

    $this->post('/oauth/authorize', validApproval((string) $authToken))
        ->assertStatus(403)
        ->assertHeaderMissing('Location');

    expect(session()->has('authRequest'))->toBeFalse()
        ->and(session()->has('authToken'))->toBeFalse()
        ->and($this->grantStore()->replacedDecisions)->toBe([])
        ->and(OAuthConsentRecord::query()->count())->toBe(0)
        ->and(DB::table('oauth_auth_codes')->count())->toBe(0);
})->with([
    'no pending request',
    'wrong auth token',
    'missing auth token',
    'another user',
    'client revoked since',
    'redirect host blocked since',
    'corrupt pending request',
    'pending request without a user',
    'pending request of a class outside the allowlist',
]);

it('accepts explicit nulls for an optional resources list and the only organisation', function (): void {
    $defaultOptions = AuthorizeFlowTestCase::defaultConsentOptions();
    $this->enableOAuth(new ConsentOptions(
        scopes: $defaultOptions->scopes,
        roles: $defaultOptions->roles,
        resources: $defaultOptions->resources,
        resourcesRequired: true,
        canGrant: true,
        organisations: [new ConsentOption('acme', 'Acme', grantable: true)],
    ));
    McpOAuthRoutes::register();
    $client = $this->createClient();
    $props = renderConsentPage($this, $this->createUser(), $client);

    // Inertia forms send unselected fields as null.
    $this->postJson('/oauth/authorize', [
        'auth_token' => $props['authToken'],
        'scopes' => ['mcp:read'],
        'role' => 'editor',
        'resources' => null,
        'all_resources' => true,
        'organisation' => null,
    ])->assertRedirect();

    $decision = $this->grantStore()->replacedDecisions[0];

    expect($decision->allResources)->toBeTrue()
        ->and($decision->attributes)->toBe(['organisation' => 'acme']);
});

it('records the only registered URI when the request omitted redirect_uri', function (string $method): void {
    $this->enableOAuth();
    McpOAuthRoutes::register();
    $client = $this->createClient(['https://solo.example/cb']);
    $props = renderConsentPage($this, $this->createUser(), $client, ['redirect_uri' => null]);

    $response = $this->call($method, '/oauth/authorize', validApproval($props['authToken']));

    expect((string) $response->headers->get('Location'))->toStartWith('https://solo.example/cb?')
        ->and(OAuthConsentRecord::query()->sole()->redirect_uri)->toBe('https://solo.example/cb');
})->with(['POST', 'DELETE']);

it('records and answers the redirect_uri the request named, not the first registered one', function (string $method): void {
    $this->enableOAuth();
    McpOAuthRoutes::register();
    $client = $this->createClient(['https://first.example/cb', 'https://second.example/cb']);
    $props = renderConsentPage($this, $this->createUser(), $client, ['redirect_uri' => 'https://second.example/cb']);

    expect($props['client']['redirectHost'])->toBe('second.example');

    $response = $this->call($method, '/oauth/authorize', validApproval($props['authToken']));

    $consentRecord = OAuthConsentRecord::query()->sole();

    expect((string) $response->headers->get('Location'))->toStartWith('https://second.example/cb?')
        ->and($consentRecord->redirect_uri)->toBe('https://second.example/cb')
        ->and($consentRecord->redirect_host)->toBe('second.example');
})->with(['POST', 'DELETE']);

it('stores at most 512 bytes of the user agent', function (): void {
    $this->enableOAuth();
    McpOAuthRoutes::register();
    $client = $this->createClient();
    $props = renderConsentPage($this, $this->createUser(), $client);

    $this->delete('/oauth/authorize', ['auth_token' => $props['authToken']], ['User-Agent' => str_repeat('a', 600)]);

    expect(OAuthConsentRecord::query()->sole()->user_agent)->toBe(str_repeat('a', 512));
});

it('consumes the pending request so an approval cannot be replayed', function (): void {
    $this->enableOAuth();
    McpOAuthRoutes::register();
    $client = $this->createClient();
    $props = renderConsentPage($this, $this->createUser(), $client);

    $this->post('/oauth/authorize', validApproval($props['authToken']))->assertRedirect();
    $this->post('/oauth/authorize', validApproval($props['authToken']))->assertStatus(403);

    expect(DB::table('oauth_auth_codes')->count())->toBe(1);
});

it('refuses an approval when the user may not grant anything', function (): void {
    $this->enableOAuth(new ConsentOptions(
        scopes: [new ConsentOption('mcp:read', 'Read', grantable: true)],
        roles: [],
        resources: [],
        resourcesRequired: false,
        canGrant: false,
    ));
    McpOAuthRoutes::register();
    $client = $this->createClient();
    $props = renderConsentPage($this, $this->createUser(), $client);

    expect($props['options']['canGrant'])->toBeFalse();

    $this->post('/oauth/authorize', ['auth_token' => $props['authToken'], 'scopes' => ['mcp:read']])
        ->assertStatus(403);

    expect($this->grantStore()->replacedDecisions)->toBe([]);
});

it('judges the posted choices against the offered options, never the form', function (array $overrides, string $errorField): void {
    $consentProvider = $this->enableOAuth();
    McpOAuthRoutes::register();
    $client = $this->createClient();
    $props = renderConsentPage($this, $this->createUser(), $client);

    $this->postJson('/oauth/authorize', validApproval($props['authToken'], $overrides))
        ->assertStatus(422)
        ->assertJsonValidationErrors([$errorField]);

    expect($this->grantStore()->replacedDecisions)->toBe([])
        ->and($consentProvider->validatedDecisions)->toBe([])
        ->and(OAuthConsentRecord::query()->count())->toBe(0)
        ->and(session()->has('authRequest'))->toBeTrue();
})->with([
    'scope not grantable' => [['scopes' => ['admin']], 'scopes.0'],
    'scope not offered' => [['scopes' => ['mcp:read', 'billing']], 'scopes.1'],
    'no scope' => [['scopes' => []], 'scopes'],
    'scopes as a string' => [['scopes' => 'mcp:read'], 'scopes'],
    'scopes as an object' => [['scopes' => ['first' => 'mcp:read']], 'scopes'],
    'scope that is not a string' => [['scopes' => [['mcp:read']]], 'scopes.0'],
    'resources as an object' => [['resources' => ['first' => 'news']], 'resources'],
    'role that is not a string' => [['role' => ['editor']], 'role'],
    'duplicate scopes' => [['scopes' => ['mcp:read', 'mcp:read']], 'scopes.0'],
    'duplicate resources' => [['resources' => ['news', 'news']], 'resources.0'],
    'role not grantable' => [['role' => 'owner'], 'role'],
    'role not offered' => [['role' => 'super-admin'], 'role'],
    'missing role' => [['role' => null], 'role'],
    'resource not grantable' => [['resources' => ['secret']], 'resources.0'],
    'resource not offered' => [['resources' => ['payroll']], 'resources.0'],
    'silence is not every resource' => [['resources' => []], 'resources'],
    'resources omitted' => [['resources' => null], 'resources'],
    'all_resources not a boolean' => [['all_resources' => 'yes'], 'all_resources'],
    'organisation when none is offered' => [['organisation' => 'acme'], 'organisation'],
]);

it('refuses a role when the product offers no role choice', function (): void {
    $this->enableOAuth(new ConsentOptions(
        scopes: [new ConsentOption('mcp:read', 'Read', grantable: true)],
        roles: [],
        resources: [],
        resourcesRequired: false,
        canGrant: true,
    ));
    McpOAuthRoutes::register();
    $client = $this->createClient();
    $props = renderConsentPage($this, $this->createUser(), $client);

    $this->postJson('/oauth/authorize', ['auth_token' => $props['authToken'], 'scopes' => ['mcp:read'], 'role' => 'editor'])
        ->assertStatus(422)
        ->assertJsonValidationErrors(['role']);

    $this->post('/oauth/authorize', ['auth_token' => $props['authToken'], 'scopes' => ['mcp:read']])
        ->assertRedirect();

    $decision = $this->grantStore()->replacedDecisions[0];

    expect($decision->role)->toBeNull()
        ->and($decision->resources)->toBe([])
        ->and($decision->allResources)->toBeFalse();
});

it('asks for the organisation when the user belongs to more than one', function (array $posted, ?string $errorField, ?string $organisation): void {
    $defaultOptions = AuthorizeFlowTestCase::defaultConsentOptions();
    $this->enableOAuth(new ConsentOptions(
        scopes: $defaultOptions->scopes,
        roles: $defaultOptions->roles,
        resources: $defaultOptions->resources,
        resourcesRequired: true,
        canGrant: true,
        organisations: [
            new ConsentOption('0193b6a4-0000-7000-8000-00000000000a', 'Acme', grantable: true),
            new ConsentOption('0193b6a4-0000-7000-8000-00000000000b', 'Globex', grantable: true),
            new ConsentOption('0193b6a4-0000-7000-8000-00000000000c', 'Initech', grantable: false),
        ],
    ));
    McpOAuthRoutes::register();
    $client = $this->createClient();
    $props = renderConsentPage($this, $this->createUser(), $client);

    expect($props['options']['organisations'][1]['label'])->toBe('Globex');

    $response = $this->postJson('/oauth/authorize', validApproval($props['authToken'], $posted));

    if ($errorField !== null) {
        $response->assertStatus(422)->assertJsonValidationErrors([$errorField]);

        expect($this->grantStore()->replacedDecisions)->toBe([]);

        return;
    }

    $response->assertRedirect();

    expect($this->grantStore()->replacedDecisions[0]->attributes)->toBe(['organisation' => $organisation])
        ->and(OAuthConsentRecord::query()->sole()->attributes)->toBe(['organisation' => $organisation]);
})->with([
    'missing' => [[], 'organisation', null],
    'not offered' => [['organisation' => 'umbrella'], 'organisation', null],
    'not grantable' => [['organisation' => '0193b6a4-0000-7000-8000-00000000000c'], 'organisation', null],
    'chosen' => [['organisation' => '0193b6a4-0000-7000-8000-00000000000b'], null, '0193b6a4-0000-7000-8000-00000000000b'],
]);

it('uses the only organisation without asking, and refuses one it was not offered', function (): void {
    $defaultOptions = AuthorizeFlowTestCase::defaultConsentOptions();
    $this->enableOAuth(new ConsentOptions(
        scopes: $defaultOptions->scopes,
        roles: $defaultOptions->roles,
        resources: $defaultOptions->resources,
        resourcesRequired: true,
        canGrant: true,
        organisations: [new ConsentOption('acme', 'Acme', grantable: true)],
    ));
    McpOAuthRoutes::register();
    $client = $this->createClient();
    $props = renderConsentPage($this, $this->createUser(), $client);

    $this->postJson('/oauth/authorize', validApproval($props['authToken'], ['organisation' => 'globex']))
        ->assertStatus(422)
        ->assertJsonValidationErrors(['organisation']);

    $this->post('/oauth/authorize', validApproval($props['authToken']))->assertRedirect();

    expect($this->grantStore()->replacedDecisions[0]->attributes)->toBe(['organisation' => 'acme']);
});

it('refuses the only organisation when it is not grantable', function (): void {
    $defaultOptions = AuthorizeFlowTestCase::defaultConsentOptions();
    $this->enableOAuth(new ConsentOptions(
        scopes: $defaultOptions->scopes,
        roles: $defaultOptions->roles,
        resources: $defaultOptions->resources,
        resourcesRequired: true,
        canGrant: true,
        organisations: [new ConsentOption('acme', 'Acme', grantable: false)],
    ));
    McpOAuthRoutes::register();
    $client = $this->createClient();
    $props = renderConsentPage($this, $this->createUser(), $client);

    $this->postJson('/oauth/authorize', validApproval($props['authToken']))
        ->assertStatus(422)
        ->assertJsonValidationErrors(['organisation']);
});

it('lets the product refuse the decision after the package checks', function (): void {
    $this->enableOAuth();
    app()->instance(ConsentProvider::class, new FakeConsentProvider(
        AuthorizeFlowTestCase::defaultConsentOptions(),
        static function (ConsentDecision $decision): void {
            throw ValidationException::withMessages(['scopes' => 'The product refuses this combination.']);
        },
    ));
    McpOAuthRoutes::register();
    $client = $this->createClient();
    $props = renderConsentPage($this, $this->createUser(), $client);

    $this->postJson('/oauth/authorize', validApproval($props['authToken']))
        ->assertStatus(422)
        ->assertJsonValidationErrors(['scopes']);

    expect($this->grantStore()->replacedDecisions)->toBe([])
        ->and(OAuthConsentRecord::query()->count())->toBe(0);
});

it('revokes the earlier codes and tokens of the same client and user on a new consent', function (): void {
    $this->enableOAuth();
    McpOAuthRoutes::register();
    $client = $this->createClient();
    $otherClient = $this->createClient();
    $user = $this->createUser();
    $otherUser = $this->createUser();
    $clientId = (string) $client->getKey();

    $insertCredentials = static function (string $suffix, string $credentialClientId, string $userId): void {
        DB::table('oauth_auth_codes')->insert(['id' => 'code-'.$suffix, 'user_id' => $userId, 'client_id' => $credentialClientId, 'scopes' => '["mcp:use"]', 'revoked' => false, 'expires_at' => now()->addMinutes(5)]);
        DB::table('oauth_access_tokens')->insert(['id' => 'token-'.$suffix, 'user_id' => $userId, 'client_id' => $credentialClientId, 'scopes' => '["mcp:use"]', 'revoked' => false, 'created_at' => now(), 'updated_at' => now(), 'expires_at' => now()->addHour()]);
        DB::table('oauth_refresh_tokens')->insert(['id' => 'refresh-'.$suffix, 'access_token_id' => 'token-'.$suffix, 'revoked' => false, 'expires_at' => now()->addDays(30)]);
    };

    $insertCredentials('mine', $clientId, (string) $user->getKey());
    $insertCredentials('other-user', $clientId, (string) $otherUser->getKey());
    $insertCredentials('other-client', (string) $otherClient->getKey(), (string) $user->getKey());

    $props = renderConsentPage($this, $user, $client);
    $this->post('/oauth/authorize', validApproval($props['authToken']))->assertRedirect();

    $isRevoked = static fn (string $table, string $id): bool => (bool) DB::table($table)->where('id', $id)->value('revoked');

    expect($isRevoked('oauth_auth_codes', 'code-mine'))->toBeTrue()
        ->and($isRevoked('oauth_access_tokens', 'token-mine'))->toBeTrue()
        ->and($isRevoked('oauth_refresh_tokens', 'refresh-mine'))->toBeTrue()
        ->and($isRevoked('oauth_auth_codes', 'code-other-user'))->toBeFalse()
        ->and($isRevoked('oauth_access_tokens', 'token-other-user'))->toBeFalse()
        ->and($isRevoked('oauth_refresh_tokens', 'refresh-other-user'))->toBeFalse()
        ->and($isRevoked('oauth_auth_codes', 'code-other-client'))->toBeFalse()
        ->and($isRevoked('oauth_access_tokens', 'token-other-client'))->toBeFalse()
        ->and($isRevoked('oauth_refresh_tokens', 'refresh-other-client'))->toBeFalse()
        ->and(DB::table('oauth_auth_codes')->where('client_id', $clientId)->where('user_id', $user->getKey())->where('revoked', false)->count())->toBe(1);
});

it('sends a guest approval or denial to login', function (string $method): void {
    $this->enableOAuth();
    McpOAuthRoutes::register();

    $this->call($method, '/oauth/authorize', ['auth_token' => 'x'])->assertRedirect('/login');
})->with(['POST', 'DELETE']);

it('refuses an approval or denial from a user whose email is not verified', function (string $method): void {
    $this->enableOAuth();
    McpOAuthRoutes::register();
    $props = renderConsentPage($this, $this->createUser(isEmailVerified: false), $this->createClient());

    $this->json($method, '/oauth/authorize', validApproval($props['authToken']))
        ->assertStatus(403)
        ->assertHeaderMissing('Location');

    expect(OAuthConsentRecord::query()->count())->toBe(0)
        ->and($this->grantStore()->replacedDecisions)->toBe([]);
})->with(['POST', 'DELETE']);

it('protects approve and deny with the CSRF token', function (string $method): void {
    $this->enableOAuth();
    McpOAuthRoutes::register();
    $client = $this->createClient();
    $props = renderConsentPage($this, $this->createUser(), $client);
    // Laravel skips CSRF checks while running unit tests; leave testing mode.
    $this->app['env'] = 'local';

    $this->call($method, '/oauth/authorize', validApproval($props['authToken']))->assertStatus(419);

    $this->call($method, '/oauth/authorize', validApproval($props['authToken'], ['_token' => session()->token()]))
        ->assertRedirect();
})->with(['POST', 'DELETE']);

// --- Deny --------------------------------------------------------------------

it('denies: access_denied with state and iss, a denied record kept 90 days, nothing granted', function (): void {
    Event::fake([McpConsentDenied::class]);
    $this->enableOAuth();
    McpOAuthRoutes::register();
    $client = $this->createClient();
    $user = $this->createUser();
    $props = renderConsentPage($this, $user, $client);
    $this->freezeSecond();

    $response = $this->delete('/oauth/authorize', ['auth_token' => $props['authToken']]);

    $location = (string) $response->headers->get('Location');
    $parameters = queryOfLocation($location);

    expect($response->getStatusCode())->toBe(302)
        ->and($location)->toStartWith(AuthorizeFlowTestCase::REGISTERED_REDIRECT_URI.'?')
        ->and($parameters['error'])->toBe('access_denied')
        ->and($parameters['state'])->toBe('state-1234')
        ->and($parameters['iss'])->toBe('https://mcp-oauth.test')
        ->and($parameters)->not->toHaveKey('code')
        ->and($this->grantStore()->replacedDecisions)->toBe([])
        ->and(DB::table('oauth_auth_codes')->count())->toBe(0)
        ->and(session()->has('authRequest'))->toBeFalse();

    $consentRecord = OAuthConsentRecord::query()->sole();

    expect($consentRecord->decision)->toBe('denied')
        ->and($consentRecord->grant_id)->toBeNull()
        ->and($consentRecord->granted_scopes)->toBeNull()
        ->and($consentRecord->requested_scopes)->toBe(['mcp:use'])
        ->and($consentRecord->redirect_host)->toBe('app.example')
        ->and($consentRecord->retention_until?->toDateTimeString())->toBe(now()->addDays(90)->toDateTimeString());

    Event::assertDispatched(McpConsentDenied::class, static fn (McpConsentDenied $event): bool => $event->clientId === (string) $client->getKey()
        && $event->userIdentifier === (string) $user->getKey());
});

it('leaves an Inertia denial with a full-page location to the client', function (): void {
    $this->enableOAuth();
    McpOAuthRoutes::register();
    $client = $this->createClient();
    $props = renderConsentPage($this, $this->createUser(), $client);

    $response = $this->delete('/oauth/authorize', ['auth_token' => $props['authToken']], INERTIA_HEADERS);

    $response->assertStatus(409);
    expect((string) $response->headers->get('X-Inertia-Location'))->toContain('error=access_denied');
});

it('refuses a denial without a pending request and records nothing', function (): void {
    $this->enableOAuth();
    McpOAuthRoutes::register();

    $this->actingAs($this->createUser())
        ->delete('/oauth/authorize', ['auth_token' => 'guess'])
        ->assertStatus(403)
        ->assertHeaderMissing('Location');

    expect(OAuthConsentRecord::query()->count())->toBe(0);
});

// --- Review hardening (SF1–SF3, prompt=login) -------------------------------

it('never skips consent, even when the product client model would', function (): void {
    $this->enableOAuth();
    Passport::useClientModel(SkippingAuthorizationClient::class);
    McpOAuthRoutes::register();
    $client = $this->createClient();

    try {
        $response = $this->actingAs($this->createUser())->get($this->authorizeUrl($client));
    } finally {
        Passport::useClientModel(Client::class);
    }

    $response->assertStatus(500)->assertHeaderMissing('Location');

    expect(DB::table('oauth_auth_codes')->count())->toBe(0)
        ->and($this->grantStore()->replacedDecisions)->toBe([]);
});

it('keeps the framing headers on a CSRF failure and an unsupported method', function (): void {
    $this->enableOAuth();
    McpOAuthRoutes::register();
    $client = $this->createClient();
    $props = renderConsentPage($this, $this->createUser(), $client);
    $unsupportedMethod = $this->put('/oauth/authorize');
    // Laravel skips CSRF checks while running unit tests; leave testing mode.
    $this->app['env'] = 'local';

    $csrfFailure = $this->post('/oauth/authorize', validApproval($props['authToken']));

    $csrfFailure->assertStatus(419)->assertHeader('X-Frame-Options', 'DENY');
    $unsupportedMethod->assertStatus(405)->assertHeader('X-Frame-Options', 'DENY');

    expect($csrfFailure->headers->all('content-security-policy'))->toContain("frame-ancestors 'none'")
        ->and($unsupportedMethod->headers->all('content-security-policy'))->toContain("frame-ancestors 'none'");
});

it('keeps the framing headers on the browser 503 page', function (): void {
    $this->enableOAuth();
    config()->set('passport.private_key', '');
    config()->set('passport.public_key', '');
    $missingKeyDirectory = sys_get_temp_dir().'/mcp-oauth-framing-no-keys-'.uniqid('', true);
    mkdir($missingKeyDirectory, 0700);
    Passport::loadKeysFrom($missingKeyDirectory);
    McpOAuthRoutes::register();

    $response = $this->get($this->authorizeUrl($this->createClient()), ['Accept' => 'text/html']);

    $response->assertStatus(503)->assertHeader('X-Frame-Options', 'DENY');

    expect($response->headers->all('content-security-policy'))->toContain("frame-ancestors 'none'");
});

it('replaces an iss the registered redirect URI already carries', function (): void {
    $this->enableOAuth();
    McpOAuthRoutes::register();
    $redirectUri = 'https://app.example/callback?iss=https%3A%2F%2Fevil.example&next=/a?b=1&tenant=7';
    $client = $this->createClient([$redirectUri]);

    $response = $this->actingAs($this->createUser())
        ->get($this->authorizeUrl($client, ['prompt' => 'none', 'redirect_uri' => $redirectUri]));

    $query = Str::after((string) $response->headers->get('Location'), '?');
    $issValues = array_values(array_filter(
        explode('&', $query),
        static fn (string $pair): bool => urldecode(Str::before($pair, '=')) === 'iss',
    ));

    expect($issValues)->toBe(['iss='.urlencode('https://mcp-oauth.test')])
        ->and(queryOfLocation((string) $response->headers->get('Location')))->toMatchArray([
            'next' => '/a?b=1',
            'tenant' => '7',
            'error' => 'consent_required',
            'state' => 'state-1234',
        ]);
});

it('ignores prompt=login, so a link cannot sign the user out', function (string $prompt): void {
    $this->enableOAuth();
    McpOAuthRoutes::register();
    $user = $this->createUser();

    $this->actingAs($user)
        ->get($this->authorizeUrl($this->createClient(), ['prompt' => $prompt]), INERTIA_HEADERS)
        ->assertOk()
        ->assertJsonPath('component', 'oauth/authorize');

    $this->assertAuthenticatedAs($user);
})->with(['login', 'login consent', 'consent login']);
