<?php

declare(strict_types=1);

use Illuminate\Cache\RateLimiting\Limit;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Support\Facades\Schema;
use Illuminate\Testing\TestResponse;
use Laravel\Passport\Client;
use Laravel\Passport\Passport;
use League\OAuth2\Server\AuthorizationServer;
use Qiick\McpOAuth\Actions\BindAccessTokenAction;
use Qiick\McpOAuth\Data\GrantRecord;
use Qiick\McpOAuth\Data\RevocationReason;
use Qiick\McpOAuth\Events\McpRefreshTokenReused;
use Qiick\McpOAuth\Exceptions\InvalidMcpOAuthConfigException;
use Qiick\McpOAuth\McpOAuthRoutes;
use Qiick\McpOAuth\Models\OAuthBlockedRedirectHost;
use Qiick\McpOAuth\Tests\Support\AuthorizeFlowTestCase;

uses(AuthorizeFlowTestCase::class);

/**
 * The one body every refusal of the same kind carries (RFC 6749 §5.2): no
 * `hint`, so a client cannot tell an expired code from a revoked one, a wrong
 * verifier from a code of another client, or reuse from a race.
 */
const INVALID_GRANT_BODY = [
    'error' => 'invalid_grant',
    'error_description' => 'The authorization code or refresh token is invalid, expired or revoked, does not match the redirect URI, or was issued to another client.',
];

const INVALID_CLIENT_BODY = [
    'error' => 'invalid_client',
    'error_description' => 'Client authentication failed.',
];

const INVALID_REQUEST_BODY = [
    'error' => 'invalid_request',
    'error_description' => 'The request is missing a required parameter, repeats a parameter or is otherwise malformed.',
];

const UNSUPPORTED_GRANT_TYPE_BODY = [
    'error' => 'unsupported_grant_type',
    'error_description' => 'Only the authorization_code and refresh_token grants are supported.',
];

const INVALID_TARGET_BODY = [
    'error' => 'invalid_target',
    'error_description' => 'The resource parameter is required and must name this MCP endpoint.',
];

beforeEach(function (): void {
    RateLimiter::clear('token');
});

/**
 * @param  array<string, mixed>  $parameters
 * @param  array<string, string>  $headers
 */
function postToken(AuthorizeFlowTestCase $testCase, array $parameters, array $headers = []): TestResponse
{
    // RFC 6749 §4.1.3: the token request is form-encoded.
    return $testCase->withHeaders(['Accept' => 'application/json', ...$headers])->post('/oauth/token', $parameters);
}

/**
 * Runs the whole browser flow and exchanges the code.
 *
 * @return array{access_token: string, refresh_token: string, user_id: string}
 */
function issueTokens(AuthorizeFlowTestCase $testCase, Client $client): array
{
    $authorization = $testCase->obtainAuthorizationCode($client);

    $response = postToken($testCase, $testCase->codeExchange($client, $authorization['code']))->assertOk();

    return [
        'access_token' => (string) $response->json('access_token'),
        'refresh_token' => (string) $response->json('refresh_token'),
        'user_id' => (string) $authorization['user']->getKey(),
    ];
}

/**
 * @return array<string, mixed>
 */
function refreshRequest(Client $client, string $refreshToken, array $overrides = []): array
{
    return array_filter(array_merge([
        'grant_type' => 'refresh_token',
        'client_id' => (string) $client->getKey(),
        'refresh_token' => $refreshToken,
        'resource' => AuthorizeFlowTestCase::RESOURCE,
    ], $overrides), static fn (mixed $value): bool => $value !== null);
}

// --- Off gate (design §4.2) --------------------------------------------------

it('with OAuth off matches an unregistered /oauth/token on every method', function (string $method, string $accept): void {
    config()->set('app.debug', false);
    config()->set('mcp-oauth.enabled', false);
    $server = ['HTTP_ACCEPT' => $accept];

    $unregisteredResponse = $this->call($method, '/oauth/token', ['grant_type' => 'authorization_code'], server: $server);

    McpOAuthRoutes::register();

    $gatedResponse = $this->call($method, '/oauth/token', ['grant_type' => 'authorization_code'], server: $server);

    expect($gatedResponse->getStatusCode())->toBe(404)
        ->and($gatedResponse->getStatusCode())->toBe($unregisteredResponse->getStatusCode())
        ->and($gatedResponse->headers->get('Allow'))->toBe($unregisteredResponse->headers->get('Allow'))
        ->and($gatedResponse->headers->has('Set-Cookie'))->toBe($unregisteredResponse->headers->has('Set-Cookie'));

    if ($method !== 'HEAD') {
        expect($gatedResponse->getContent())->toBe($unregisteredResponse->getContent());
    }
})->with(['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'])
    ->with(['application/json', 'text/html']);

it('answers 405 with Allow: POST on other methods when OAuth is on', function (string $method): void {
    $this->enableOAuth();
    McpOAuthRoutes::register();

    $this->call($method, '/oauth/token')
        ->assertStatus(405)
        ->assertHeader('Allow', 'POST');
})->with(['GET', 'HEAD', 'PUT', 'PATCH', 'DELETE', 'OPTIONS']);

it('answers a JSON 503 when Passport keys are missing', function (): void {
    $this->enableOAuth();
    config()->set('passport.private_key', '');
    config()->set('passport.public_key', '');
    $missingKeyDirectory = sys_get_temp_dir().'/mcp-oauth-token-no-keys-'.uniqid('', true);
    mkdir($missingKeyDirectory, 0700);
    Passport::loadKeysFrom($missingKeyDirectory);
    McpOAuthRoutes::register();
    $client = $this->createClient();

    postToken($this, $this->codeExchange($client, 'any-code'))
        ->assertStatus(503)
        ->assertJsonPath('error', 'temporarily_unavailable');
});

it('is named passport.token, stateless and throttled with mcp-oauth-token', function (): void {
    $this->enableOAuth();
    McpOAuthRoutes::register();
    $route = app('router')->getRoutes()->getByName('passport.token');

    expect($route)->not->toBeNull()
        ->and($route->uri())->toBe('oauth/token')
        ->and($route->gatherMiddleware())->toContain('throttle:mcp-oauth-token')
        ->and($route->gatherMiddleware())->not->toContain('web');
});

it('throttles the token endpoint with mcp-oauth-token', function (): void {
    $this->enableOAuth();
    McpOAuthRoutes::register();
    $client = $this->createClient();
    RateLimiter::for('mcp-oauth-token', static fn (Request $request): Limit => Limit::perMinute(2)->by('token'));

    postToken($this, $this->codeExchange($client, 'garbage'))->assertStatus(400);
    postToken($this, $this->codeExchange($client, 'garbage'))->assertStatus(400);
    postToken($this, $this->codeExchange($client, 'garbage'))->assertStatus(429);
});

// --- Authorization code with PKCE (design §5.2 item 6, S16, S18, S21) ------

it('exchanges a code for a bound token pair that names the wire scope', function (): void {
    $this->enableOAuth();
    McpOAuthRoutes::register();
    $client = $this->createClient();

    ['code' => $code, 'user' => $user] = $this->obtainAuthorizationCode($client);

    $response = postToken($this, $this->codeExchange($client, $code))
        ->assertOk()
        ->assertJsonPath('token_type', 'Bearer')
        ->assertJsonPath('scope', 'mcp:use');

    expect($response->json('access_token'))->toBeString()->not->toBe('')
        ->and($response->json('refresh_token'))->toBeString()->not->toBe('')
        ->and($response->headers->get('Cache-Control'))->toContain('no-store');

    $grant = $this->grantStore()->activeFor((string) $client->getKey(), (string) $user->getKey());
    $tokenRow = DB::table('oauth_access_tokens')->where('client_id', $client->getKey())->sole();

    expect($grant)->not->toBeNull()
        ->and($tokenRow->api_key_id)->toBe($grant->id)
        ->and($tokenRow->audience)->toBe(AuthorizeFlowTestCase::RESOURCE)
        ->and((bool) $tokenRow->revoked)->toBeFalse();
});

it('binds through the configured grant binding column', function (): void {
    $this->enableOAuth();
    config()->set('mcp-oauth.grant_binding_column', 'grant_uuid');
    Schema::table('oauth_access_tokens', static function (Blueprint $table): void {
        $table->uuid('grant_uuid')->nullable();
    });
    McpOAuthRoutes::register();
    $client = $this->createClient();

    issueTokens($this, $client);

    $tokenRow = DB::table('oauth_access_tokens')->where('client_id', $client->getKey())->sole();

    expect($tokenRow->grant_uuid)->toBeString()
        ->and($tokenRow->api_key_id)->toBeNull();
});

it('refuses a grant binding column that is not a non-empty string', function (mixed $bindingColumn): void {
    $this->enableOAuth();
    $client = $this->createClient();
    $user = $this->createUser();
    $this->grantStore()->seed(new GrantRecord(
        id: '0195f0a0-0000-7000-8000-00000000beef',
        clientId: (string) $client->getKey(),
        userIdentifier: (string) $user->getKey(),
        revoked: false,
        scopes: ['mcp:read'],
        authorizedAt: null,
        lastUsedAt: null,
    ));
    config()->set('mcp-oauth.grant_binding_column', $bindingColumn);

    expect(fn () => app(BindAccessTokenAction::class)->execute('any-token', (string) $user->getKey(), (string) $client->getKey()))
        ->toThrow(InvalidMcpOAuthConfigException::class, 'grant_binding_column');
})->with(['empty' => [''], 'not a string' => [['api_key_id']], 'missing' => [null]]);

it('revokes at once a token minted for a grant revoked before the exchange', function (): void {
    $this->enableOAuth();
    McpOAuthRoutes::register();
    $client = $this->createClient();
    ['code' => $code, 'user' => $user] = $this->obtainAuthorizationCode($client);
    $grant = $this->grantStore()->activeFor((string) $client->getKey(), (string) $user->getKey());
    $this->grantStore()->revoke($grant->id, null, RevocationReason::User);

    postToken($this, $this->codeExchange($client, $code))->assertOk();

    $tokenRow = DB::table('oauth_access_tokens')->where('client_id', $client->getKey())->sole();

    expect((bool) $tokenRow->revoked)->toBeTrue()
        ->and($tokenRow->api_key_id)->toBeNull()
        ->and($tokenRow->audience)->toBeNull();
});

it('refuses a code exchange without the PKCE verifier', function (): void {
    $this->enableOAuth();
    McpOAuthRoutes::register();
    $client = $this->createClient();
    ['code' => $code] = $this->obtainAuthorizationCode($client);

    postToken($this, $this->codeExchange($client, $code, ['code_verifier' => null]))
        ->assertStatus(400)
        ->assertExactJson(INVALID_REQUEST_BODY);

    expect(DB::table('oauth_access_tokens')->count())->toBe(0);
});

// Expiry is league's check against PHP's time(), which travel() cannot move;
// it is an invalid_grant like these and goes through the same renderer.
it('answers every refused code with the same invalid_grant body', function (Closure $tamper): void {
    $this->enableOAuth();
    McpOAuthRoutes::register();
    $client = $this->createClient();
    ['code' => $code] = $this->obtainAuthorizationCode($client);

    $parameters = $tamper($this, $client, $code);

    postToken($this, $parameters)
        ->assertStatus(400)
        ->assertExactJson(INVALID_GRANT_BODY);
})->with([
    'wrong verifier' => [static fn ($testCase, Client $client, string $code): array => $testCase->codeExchange($client, $code, ['code_verifier' => str_repeat('w', 43)])],
    'garbage code' => [static fn ($testCase, Client $client, string $code): array => $testCase->codeExchange($client, 'not-an-encrypted-code')],
    'other redirect_uri' => [static fn ($testCase, Client $client, string $code): array => $testCase->codeExchange($client, $code, ['redirect_uri' => 'https://app.example/other'])],
    'code of another client' => [static function ($testCase, Client $client, string $code): array {
        $otherClient = $testCase->createClient();

        return $testCase->codeExchange($otherClient, $code);
    }],
    'replayed code' => [static function ($testCase, Client $client, string $code): array {
        postToken($testCase, $testCase->codeExchange($client, $code))->assertOk();

        return $testCase->codeExchange($client, $code);
    }],
]);

// --- Grant types, resource and client (S16, S19, S37, S38) ----------------

it('accepts only the authorization code and refresh token grants', function (mixed $grantType): void {
    $this->enableOAuth();
    McpOAuthRoutes::register();
    $client = $this->createClient();

    postToken($this, ['grant_type' => $grantType, 'client_id' => (string) $client->getKey(), 'scope' => 'mcp:use', 'resource' => AuthorizeFlowTestCase::RESOURCE])
        ->assertStatus(400)
        ->assertExactJson(UNSUPPORTED_GRANT_TYPE_BODY);
})->with([
    'client_credentials' => ['client_credentials'],
    'password' => ['password'],
    'device code' => ['urn:ietf:params:oauth:grant-type:device_code'],
    'personal access' => ['personal_access'],
    'implicit' => ['implicit'],
    'missing' => [null],
    'repeated' => [['authorization_code', 'refresh_token']],
]);

it('requires the resource to name this MCP endpoint on both grants', function (string $grantType, mixed $resource): void {
    $this->enableOAuth();
    McpOAuthRoutes::register();
    $client = $this->createClient();
    $parameters = $grantType === 'authorization_code'
        ? $this->codeExchange($client, 'any-code', ['resource' => $resource])
        : refreshRequest($client, 'any-refresh-token', ['resource' => $resource]);

    postToken($this, $parameters)
        ->assertStatus(400)
        ->assertExactJson(INVALID_TARGET_BODY);
})->with(['authorization_code', 'refresh_token'])
    ->with([
        'missing' => [null],
        'another server' => ['https://elsewhere.example/mcp'],
        'a prefix' => ['https://mcp-oauth.test/mc'],
        'a longer path' => ['https://mcp-oauth.test/mcp/extra'],
        'repeated' => [[AuthorizeFlowTestCase::RESOURCE, AuthorizeFlowTestCase::RESOURCE]],
    ]);

it('refuses unknown, malformed and revoked clients as invalid_client', function (string $clientCase): void {
    $this->enableOAuth();
    McpOAuthRoutes::register();
    $client = $this->createClient(isRevoked: $clientCase === 'revoked');
    $clientId = match ($clientCase) {
        'unknown' => '0195f0a0-0000-7000-8000-000000000000',
        'not a uuid' => 'not-a-uuid',
        default => (string) $client->getKey(),
    };
    DB::enableQueryLog();

    postToken($this, $this->codeExchange($client, 'any-code', ['client_id' => $clientId]))
        ->assertStatus(401)
        ->assertExactJson(INVALID_CLIENT_BODY);

    if ($clientCase === 'not a uuid') {
        $clientQueries = array_filter(DB::getQueryLog(), static fn (array $query): bool => str_contains($query['query'], 'oauth_clients'));

        expect($clientQueries)->toBe([]);
    }
})->with(['unknown', 'not a uuid', 'revoked']);

it('refuses a client whose redirect host was blocked, by body or HTTP Basic client_id', function (string $clientIdSource): void {
    $this->enableOAuth();
    McpOAuthRoutes::register();
    $client = $this->createClient();
    ['code' => $code] = $this->obtainAuthorizationCode($client);
    OAuthBlockedRedirectHost::query()->create(['host' => 'app.example']);
    $parameters = $this->codeExchange($client, $code);
    $headers = [];

    if ($clientIdSource === 'basic') {
        unset($parameters['client_id']);
        $headers['Authorization'] = 'Basic '.base64_encode($client->getKey().':');
    }

    $response = postToken($this, $parameters, $headers)
        ->assertStatus(401)
        ->assertExactJson(INVALID_CLIENT_BODY);

    if ($clientIdSource === 'basic') {
        $response->assertHeader('WWW-Authenticate', 'Basic realm="OAuth"');
    }

    expect(DB::table('oauth_access_tokens')->count())->toBe(0);
})->with(['body', 'basic']);

it('exchanges a code for a client named only in HTTP Basic', function (): void {
    $this->enableOAuth();
    McpOAuthRoutes::register();
    $client = $this->createClient();
    ['code' => $code] = $this->obtainAuthorizationCode($client);

    postToken($this, $this->codeExchange($client, $code, ['client_id' => null]), ['Authorization' => 'Basic '.base64_encode($client->getKey().':')])
        ->assertOk()
        ->assertJsonPath('token_type', 'Bearer');
});

it('leaves a missing or repeated client_id to league as invalid_request', function (mixed $clientId): void {
    $this->enableOAuth();
    McpOAuthRoutes::register();
    $client = $this->createClient();

    postToken($this, $this->codeExchange($client, 'any-code', ['client_id' => $clientId]))
        ->assertStatus(400)
        ->assertExactJson(INVALID_REQUEST_BODY);
})->with([
    'missing' => [null],
    'repeated' => [['0195f0a0-0000-7000-8000-000000000000', '0195f0a0-0000-7000-8000-000000000001']],
]);

it('refuses the password grant even when Passport has it enabled', function (): void {
    Passport::enablePasswordGrant();
    app()->forgetInstance(AuthorizationServer::class);

    try {
        $this->enableOAuth();
        McpOAuthRoutes::register();
        $client = $this->createClient();

        postToken($this, [
            'grant_type' => 'password',
            'client_id' => (string) $client->getKey(),
            'username' => 'someone@example.com',
            'password' => 'secret',
            'resource' => AuthorizeFlowTestCase::RESOURCE,
        ])
            ->assertStatus(400)
            ->assertExactJson(UNSUPPORTED_GRANT_TYPE_BODY);
    } finally {
        Passport::$passwordGrantEnabled = false;
    }
});

// --- Refresh tokens (design §8.4, S56, S59) --------------------------------

it('rotates a refresh token into a new bound pair', function (): void {
    $this->enableOAuth();
    McpOAuthRoutes::register();
    $client = $this->createClient();
    $tokens = issueTokens($this, $client);

    $response = postToken($this, refreshRequest($client, $tokens['refresh_token']))
        ->assertOk()
        ->assertJsonPath('scope', 'mcp:use');

    expect($response->json('refresh_token'))->not->toBe($tokens['refresh_token']);

    $grant = $this->grantStore()->activeFor((string) $client->getKey(), $tokens['user_id']);
    $liveTokens = DB::table('oauth_access_tokens')->where('client_id', $client->getKey())->where('revoked', false)->get();

    expect($liveTokens)->toHaveCount(1)
        ->and($liveTokens->sole()->api_key_id)->toBe($grant->id)
        ->and($liveTokens->sole()->audience)->toBe(AuthorizeFlowTestCase::RESOURCE);
});

it('revokes the family and the grant when a used refresh token comes back', function (): void {
    Event::fake([McpRefreshTokenReused::class]);
    $this->enableOAuth();
    McpOAuthRoutes::register();
    $client = $this->createClient();
    $tokens = issueTokens($this, $client);
    $grant = $this->grantStore()->activeFor((string) $client->getKey(), $tokens['user_id']);
    $rotated = postToken($this, refreshRequest($client, $tokens['refresh_token']))->assertOk();

    postToken($this, refreshRequest($client, $tokens['refresh_token']))
        ->assertStatus(400)
        ->assertExactJson(INVALID_GRANT_BODY);

    expect(DB::table('oauth_access_tokens')->where('revoked', false)->count())->toBe(0)
        ->and(DB::table('oauth_refresh_tokens')->where('revoked', false)->count())->toBe(0)
        ->and($this->grantStore()->find($grant->id)?->revoked)->toBeTrue();

    postToken($this, refreshRequest($client, (string) $rotated->json('refresh_token')))
        ->assertStatus(400)
        ->assertExactJson(INVALID_GRANT_BODY);

    Event::assertDispatched(McpRefreshTokenReused::class);
});

it('answers every refused refresh with the same invalid_grant body', function (Closure $tamper): void {
    $this->enableOAuth();
    McpOAuthRoutes::register();
    $client = $this->createClient();
    $tokens = issueTokens($this, $client);

    postToken($this, $tamper($this, $client, $tokens))
        ->assertStatus(400)
        ->assertExactJson(INVALID_GRANT_BODY);
})->with([
    'garbage refresh token' => [static fn ($testCase, Client $client, array $tokens): array => refreshRequest($client, 'not-an-encrypted-token')],
    'refresh token of another client' => [static function ($testCase, Client $client, array $tokens): array {
        return refreshRequest($testCase->createClient(), $tokens['refresh_token']);
    }],
    'grant revoked by the user' => [static function ($testCase, Client $client, array $tokens): array {
        $grant = $testCase->grantStore()->activeFor((string) $client->getKey(), $tokens['user_id']);
        $testCase->grantStore()->revoke($grant->id, $tokens['user_id'], RevocationReason::User);

        return refreshRequest($client, $tokens['refresh_token']);
    }],
]);
