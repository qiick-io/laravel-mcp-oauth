<?php

declare(strict_types=1);

use Illuminate\Cache\RateLimiting\Limit;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Http\Middleware\ConvertEmptyStringsToNull;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Str;
use Illuminate\Testing\TestResponse;
use Laravel\Passport\Client;
use Laravel\Passport\Events\AccessTokenCreated;
use Laravel\Passport\Passport;
use League\OAuth2\Server\AuthorizationServer;
use League\OAuth2\Server\CryptTrait;
use Qiick\McpOAuth\Actions\BindAccessTokenAction;
use Qiick\McpOAuth\Actions\RevokeAuthCodeTokensAction;
use Qiick\McpOAuth\Contracts\GrantStore;
use Qiick\McpOAuth\Data\GrantRecord;
use Qiick\McpOAuth\Data\RevocationReason;
use Qiick\McpOAuth\Events\McpRefreshTokenReused;
use Qiick\McpOAuth\Exceptions\InvalidMcpOAuthConfigException;
use Qiick\McpOAuth\McpOAuthRoutes;
use Qiick\McpOAuth\Models\OAuthBlockedRedirectHost;
use Qiick\McpOAuth\Models\OAuthClientMetadata;
use Qiick\McpOAuth\Tests\Support\AuthorizeFlowTestCase;
use Qiick\McpOAuth\Tests\Support\HookedGrantStore;

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

// --- One-shot codes and code reuse (RFC 6749 §4.1.2, RFC 9700 §4.5) --------

/**
 * Re-encrypts a real code with another expiry, as league would have issued it
 * earlier: league checks expiry against PHP's time(), which travel() cannot move.
 */
function expireAuthorizationCode(string $code, array $payloadOverrides = []): string
{
    $codec = new class(Passport::tokenEncryptionKey(app('encrypter')))
    {
        use CryptTrait;

        public function __construct(string $encryptionKey)
        {
            $this->setEncryptionKey($encryptionKey);
        }

        public function reseal(string $encryptedCode, array $overrides): string
        {
            $payload = json_decode($this->decrypt($encryptedCode), true);
            $payload = array_merge($payload, ['expire_time' => time() - 60], $overrides);

            return $this->encrypt((string) json_encode($payload));
        }
    };

    return $codec->reseal($code, $payloadOverrides);
}

it('burns the code on a failed exchange, so the right verifier cannot follow', function (array $failedAttempt): void {
    $this->enableOAuth();
    McpOAuthRoutes::register();
    $client = $this->createClient();
    ['code' => $code] = $this->obtainAuthorizationCode($client);

    postToken($this, $this->codeExchange($client, $code, $failedAttempt))->assertStatus(400);

    postToken($this, $this->codeExchange($client, $code))
        ->assertStatus(400)
        ->assertExactJson(INVALID_GRANT_BODY);

    expect(DB::table('oauth_access_tokens')->count())->toBe(0);
})->with([
    'wrong verifier' => [['code_verifier' => str_repeat('w', 43)]],
    'missing verifier' => [['code_verifier' => null]],
    'other redirect_uri' => [['redirect_uri' => 'https://app.example/other']],
]);

it('revokes every token issued with a code when the code comes back', function (): void {
    Log::spy();
    $this->enableOAuth();
    McpOAuthRoutes::register();
    $client = $this->createClient();
    ['code' => $code, 'user' => $user] = $this->obtainAuthorizationCode($client);
    $firstPair = postToken($this, $this->codeExchange($client, $code))->assertOk();
    postToken($this, refreshRequest($client, (string) $firstPair->json('refresh_token')))->assertOk();
    $grant = $this->grantStore()->activeFor((string) $client->getKey(), (string) $user->getKey());

    postToken($this, $this->codeExchange($client, $code))
        ->assertStatus(400)
        ->assertExactJson(INVALID_GRANT_BODY);

    expect(DB::table('oauth_access_tokens')->count())->toBe(2)
        ->and(DB::table('oauth_access_tokens')->where('revoked', false)->count())->toBe(0)
        ->and(DB::table('oauth_refresh_tokens')->where('revoked', false)->count())->toBe(0)
        ->and($this->grantStore()->find($grant->id)?->revoked)->toBeTrue()
        ->and(collect($this->grantStore()->revocations)->last())->toMatchArray([
            'grantId' => $grant->id,
            'reason' => RevocationReason::Reuse,
        ]);

    // Ids only: the code and the tokens never reach the log.
    Log::shouldHaveReceived('warning')->once()->with(
        'MCP OAuth authorization code presented again: its tokens and grant are revoked.',
        ['client_id' => (string) $client->getKey(), 'grant_id' => $grant->id],
    );
});

it('revokes the tokens of a code replayed after it expired', function (): void {
    $this->enableOAuth();
    McpOAuthRoutes::register();
    $client = $this->createClient();
    ['code' => $code] = $this->obtainAuthorizationCode($client);
    postToken($this, $this->codeExchange($client, $code))->assertOk();

    postToken($this, $this->codeExchange($client, expireAuthorizationCode($code)))
        ->assertStatus(400)
        ->assertExactJson(INVALID_GRANT_BODY);

    expect(DB::table('oauth_access_tokens')->where('revoked', false)->count())->toBe(0)
        ->and(DB::table('oauth_refresh_tokens')->where('revoked', false)->count())->toBe(0);
});

it('leaves an expired code that was never exchanged, and its user, alone', function (): void {
    $this->enableOAuth();
    McpOAuthRoutes::register();
    $client = $this->createClient();
    ['code' => $firstCode, 'user' => $user] = $this->obtainAuthorizationCode($client);
    ['code' => $secondCode] = $this->obtainAuthorizationCode($client, $user);
    postToken($this, $this->codeExchange($client, $secondCode))->assertOk();

    postToken($this, $this->codeExchange($client, expireAuthorizationCode($firstCode)))
        ->assertStatus(400)
        ->assertExactJson(INVALID_GRANT_BODY);

    expect(DB::table('oauth_access_tokens')->where('revoked', false)->count())->toBe(1)
        ->and($this->grantStore()->activeFor((string) $client->getKey(), (string) $user->getKey()))->not->toBeNull();
});

it('does not revoke a newer consent when an older code comes back', function (bool $isOlderCodeExchanged): void {
    $this->enableOAuth();
    McpOAuthRoutes::register();
    $client = $this->createClient();
    ['code' => $olderCode, 'user' => $user] = $this->obtainAuthorizationCode($client);

    if ($isOlderCodeExchanged) {
        postToken($this, $this->codeExchange($client, $olderCode))->assertOk();
    }

    ['code' => $newerCode] = $this->obtainAuthorizationCode($client, $user);
    postToken($this, $this->codeExchange($client, $newerCode))->assertOk();
    $newerGrant = $this->grantStore()->activeFor((string) $client->getKey(), (string) $user->getKey());

    postToken($this, $this->codeExchange($client, $olderCode))
        ->assertStatus(400)
        ->assertExactJson(INVALID_GRANT_BODY);

    expect($this->grantStore()->find($newerGrant->id)?->revoked)->toBeFalse()
        ->and(DB::table('oauth_access_tokens')->where('revoked', false)->count())->toBe(1)
        ->and(DB::table('oauth_refresh_tokens')->where('revoked', false)->count())->toBe(1);
})->with(['older code exchanged' => [true], 'older code never exchanged' => [false]]);

it('ignores an expired code whose payload names no string code id', function (): void {
    $this->enableOAuth();
    McpOAuthRoutes::register();
    $client = $this->createClient();
    ['code' => $code] = $this->obtainAuthorizationCode($client);
    postToken($this, $this->codeExchange($client, $code))->assertOk();

    postToken($this, $this->codeExchange($client, expireAuthorizationCode($code, ['auth_code_id' => 42])))
        ->assertStatus(400)
        ->assertExactJson(INVALID_GRANT_BODY);

    expect(DB::table('oauth_access_tokens')->where('revoked', false)->count())->toBe(1);
});

// --- Review of #16: order, recorded grant, listener scope, client auth ------

/**
 * Puts a HookedGrantStore around the current FakeGrantStore and rebuilds the
 * AuthorizationServer, whose repositories hold the store they were built with.
 */
function hookGrantStore(AuthorizeFlowTestCase $testCase): HookedGrantStore
{
    $hookedGrantStore = new HookedGrantStore($testCase->grantStore());
    app()->instance(GrantStore::class, $hookedGrantStore);
    app()->forgetInstance(AuthorizationServer::class);
    // The route keeps its controller, and with it the server, across requests.
    app('router')->getRoutes()->getByName('passport.token')?->flushController();

    return $hookedGrantStore;
}

it('revokes the grant before the tokens when a code comes back', function (): void {
    $this->enableOAuth();
    McpOAuthRoutes::register();
    $client = $this->createClient();
    ['code' => $code] = $this->obtainAuthorizationCode($client);
    postToken($this, $this->codeExchange($client, $code))->assertOk();
    $hookedGrantStore = hookGrantStore($this);
    $liveTokensWhenGrantRevoked = null;
    $hookedGrantStore->beforeRevoke = static function () use (&$liveTokensWhenGrantRevoked): void {
        $liveTokensWhenGrantRevoked = DB::table('oauth_access_tokens')->where('revoked', false)->count();
    };

    postToken($this, $this->codeExchange($client, $code))->assertStatus(400);

    // A race winner still binding its token sees a revoked grant and revokes it.
    expect($liveTokensWhenGrantRevoked)->toBe(1)
        ->and(DB::table('oauth_access_tokens')->where('revoked', false)->count())->toBe(0);
});

it('binds the token to the grant the code was consumed under, not a newer one', function (): void {
    $this->enableOAuth();
    McpOAuthRoutes::register();
    $client = $this->createClient();
    ['code' => $code, 'user' => $user] = $this->obtainAuthorizationCode($client);
    $consumedGrant = $this->grantStore()->activeFor((string) $client->getKey(), (string) $user->getKey());
    $hookedGrantStore = hookGrantStore($this);
    // A new consent lands between the code's consumption and its token.
    $hookedGrantStore->afterNextActiveFor = function () use ($consumedGrant): void {
        $this->grantStore()->revoke($consumedGrant->id, $consumedGrant->userIdentifier, RevocationReason::Reconsent);
        $this->grantStore()->seed(new GrantRecord(
            id: '0195f0a0-0000-7000-8000-0000000000b2',
            clientId: $consumedGrant->clientId,
            userIdentifier: $consumedGrant->userIdentifier,
            revoked: false,
            scopes: ['mcp:read'],
            authorizedAt: null,
            lastUsedAt: null,
        ));
    };

    postToken($this, $this->codeExchange($client, $code))->assertOk();

    $tokenRow = DB::table('oauth_access_tokens')->where('client_id', $client->getKey())->sole();

    expect($tokenRow->api_key_id)->not->toBe('0195f0a0-0000-7000-8000-0000000000b2')
        ->and((bool) $tokenRow->revoked)->toBeTrue();
});

it('does not revoke again a grant that is already revoked when its code comes back', function (): void {
    $this->enableOAuth();
    McpOAuthRoutes::register();
    $client = $this->createClient();
    ['code' => $code, 'user' => $user] = $this->obtainAuthorizationCode($client);
    postToken($this, $this->codeExchange($client, $code))->assertOk();
    $grant = $this->grantStore()->activeFor((string) $client->getKey(), (string) $user->getKey());
    $this->grantStore()->revoke($grant->id, (string) $user->getKey(), RevocationReason::User);

    postToken($this, $this->codeExchange($client, $code))->assertStatus(400);

    expect(collect($this->grantStore()->revocations)->pluck('reason')->all())->toBe([RevocationReason::User]);
});

it('binds only tokens of MCP clients and leaves the product\'s own tokens alone', function (): void {
    $this->enableOAuth();
    $personalAccessClient = $this->createClient();
    $personalAccessClient->forceFill(['grant_types' => ['personal_access']])->save();
    OAuthClientMetadata::query()->where('client_id', $personalAccessClient->getKey())->delete();
    $user = $this->createUser();
    DB::table('oauth_access_tokens')->insert([
        'id' => 'personal-token', 'user_id' => $user->getKey(), 'client_id' => $personalAccessClient->getKey(),
        'name' => 'cli', 'scopes' => '[]', 'revoked' => false, 'created_at' => now(), 'updated_at' => now(), 'expires_at' => now()->addDay(),
    ]);

    event(new AccessTokenCreated('personal-token', (string) $user->getKey(), (string) $personalAccessClient->getKey()));

    $tokenRow = DB::table('oauth_access_tokens')->where('id', 'personal-token')->sole();

    expect((bool) $tokenRow->revoked)->toBeFalse()
        ->and($tokenRow->api_key_id)->toBeNull()
        ->and($tokenRow->audience)->toBeNull();
});

it('leaves token creation alone while OAuth is off, even without adapters', function (): void {
    config()->set('mcp-oauth.enabled', false);
    app()->offsetUnset(GrantStore::class);

    expect(fn () => event(new AccessTokenCreated('any-token', '1', '0195f0a0-0000-7000-8000-000000000000')))
        ->not->toThrow(Exception::class);
});

it('refuses a client that uses HTTP Basic and the body together', function (): void {
    $this->enableOAuth();
    McpOAuthRoutes::register();
    $client = $this->createClient();
    $otherClient = $this->createClient();
    ['code' => $code] = $this->obtainAuthorizationCode($client);

    postToken($this, $this->codeExchange($client, $code), ['Authorization' => 'Basic '.base64_encode($otherClient->getKey().':')])
        ->assertStatus(400)
        ->assertExactJson(INVALID_REQUEST_BODY);

    expect(DB::table('oauth_access_tokens')->count())->toBe(0);
});

it('refuses a client_secret in the body beside HTTP Basic', function (): void {
    $this->enableOAuth();
    McpOAuthRoutes::register();
    $client = $this->createClient();
    ['code' => $code] = $this->obtainAuthorizationCode($client);

    postToken($this, $this->codeExchange($client, $code, ['client_id' => null, 'client_secret' => 'anything']), ['Authorization' => 'Basic '.base64_encode($client->getKey().':')])
        ->assertStatus(400)
        ->assertExactJson(INVALID_REQUEST_BODY);
});

it('leaves an empty client_id to league when empty strings reach the middleware', function (): void {
    ConvertEmptyStringsToNull::skipWhen(static fn (): bool => true);

    try {
        $this->enableOAuth();
        McpOAuthRoutes::register();
        $client = $this->createClient();

        postToken($this, $this->codeExchange($client, 'any-code', ['client_id' => '']))
            ->assertStatus(400)
            ->assertExactJson(INVALID_REQUEST_BODY);
    } finally {
        ConvertEmptyStringsToNull::flushState();
    }
});

it('challenges with the scheme the client used, as league does', function (): void {
    $this->enableOAuth();
    McpOAuthRoutes::register();
    $client = $this->createClient();

    postToken($this, $this->codeExchange($client, 'any-code', ['client_id' => 'not-a-uuid']), ['Authorization' => 'Bearer something'])
        ->assertStatus(401)
        ->assertHeader('WWW-Authenticate', 'Bearer realm="OAuth"');
});

// --- Re-review of #16: the race winner, MCP clients only ---------------------

it('revokes the race winner\'s token whichever side of its binding the replay lands', function (string $replayMoment): void {
    $this->enableOAuth();
    McpOAuthRoutes::register();
    $client = $this->createClient();
    ['code' => $code] = $this->obtainAuthorizationCode($client);
    $hookedGrantStore = hookGrantStore($this);
    // The loser's replay, run inside the winner's request where the race puts it.
    $replay = static function () use ($client): void {
        $codeId = (string) DB::table('oauth_auth_codes')->where('client_id', $client->getKey())->value('id');
        app(RevokeAuthCodeTokensAction::class)->execute($codeId);
    };

    if ($replayMoment === 'after the winner reads its grant') {
        $hookedGrantStore->afterNextFind = $replay;
    } else {
        $hookedGrantStore->beforeNextFind = $replay;
    }

    postToken($this, $this->codeExchange($client, $code))->assertOk();

    expect(DB::table('oauth_access_tokens')->where('client_id', $client->getKey())->where('revoked', false)->count())->toBe(0)
        ->and(collect($this->grantStore()->revocations)->pluck('reason')->all())->toContain(RevocationReason::Reuse);
})->with(['after the winner reads its grant', 'before the winner reads its grant']);

it('leaves alone the tokens of a client the package did not register', function (string $clientKind): void {
    $this->enableOAuth();
    $user = $this->createUser();
    // An authorization_code client with no oauth_client_metadata row: the
    // product's own app, or a personal access client migrated from Passport 12.
    $productClient = new Client;
    $productClient->forceFill([
        'id' => (string) Str::uuid7(),
        'name' => $clientKind,
        'secret' => null,
        'redirect_uris' => ['https://app.example/own'],
        'grant_types' => $clientKind === 'product app'
            ? ['authorization_code', 'refresh_token']
            : ['authorization_code', 'implicit', 'personal_access', 'refresh_token'],
        'revoked' => false,
    ])->save();
    DB::table('oauth_access_tokens')->insert([
        'id' => 'product-token', 'user_id' => $user->getKey(), 'client_id' => $productClient->getKey(),
        'name' => 'cli', 'scopes' => '[]', 'revoked' => false, 'created_at' => now(), 'updated_at' => now(), 'expires_at' => now()->addDay(),
    ]);

    event(new AccessTokenCreated('product-token', (string) $user->getKey(), (string) $productClient->getKey()));

    $tokenRow = DB::table('oauth_access_tokens')->where('id', 'product-token')->sole();

    expect((bool) $tokenRow->revoked)->toBeFalse()
        ->and($tokenRow->api_key_id)->toBeNull();
})->with(['product app', 'migrated personal access client']);
