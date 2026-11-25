<?php

declare(strict_types=1);

use Carbon\CarbonImmutable;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Str;
use Illuminate\Testing\TestResponse;
use Laravel\Passport\Bridge\AccessToken;
use Laravel\Passport\Bridge\Client as BridgeClient;
use Laravel\Passport\Bridge\Scope;
use Laravel\Passport\Client;
use Laravel\Passport\Passport;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use League\OAuth2\Server\CryptKey;
use Qiick\McpOAuth\AccessTokenAuthenticator;
use Qiick\McpOAuth\Contracts\ApiKeyDoor;
use Qiick\McpOAuth\Contracts\GrantAuthorizer;
use Qiick\McpOAuth\Contracts\McpCredentialBinder;
use Qiick\McpOAuth\Data\AuthorizationDecision;
use Qiick\McpOAuth\Data\GrantRecord;
use Qiick\McpOAuth\Data\RevocationReason;
use Qiick\McpOAuth\Http\Middleware\McpBearerDoorMiddleware;
use Qiick\McpOAuth\Http\Middleware\McpChallengeMiddleware;
use Qiick\McpOAuth\McpOAuthRoutes;
use Qiick\McpOAuth\Models\OAuthBlockedRedirectHost;
use Qiick\McpOAuth\Models\OAuthClientMetadata;
use Qiick\McpOAuth\Testing\FakeApiKeyDoor;
use Qiick\McpOAuth\Testing\FakeGrantAuthorizer;
use Qiick\McpOAuth\Testing\FakeMcpCredentialBinder;
use Qiick\McpOAuth\Tests\Support\AuthorizeFlowTestCase;

uses(AuthorizeFlowTestCase::class);

/**
 * The `/mcp` Bearer door (design §5.3) and the use-time checks on an OAuth
 * token (design §8.5), behind the package's RFC 6750 challenge.
 */
const RESOURCE_METADATA_URL = 'https://mcp-oauth.test/.well-known/oauth-protected-resource/mcp';

const OFF_CHALLENGE = 'Bearer realm="mcp", error="invalid_token"';

beforeEach(function (): void {
    RateLimiter::clear('mcp-auth-failures:127.0.0.1');
});

/**
 * The product's `/mcp` route: the package's challenge outside, the door inside.
 */
function registerMcpRoute(): void
{
    Route::post('mcp', static fn (Request $request) => response()->json([
        'credential' => get_debug_type($request->attributes->get('mcp_credential')),
    ]))->middleware([McpChallengeMiddleware::class, McpBearerDoorMiddleware::class]);
}

function callMcp(AuthorizeFlowTestCase $testCase, ?string $bearer): TestResponse
{
    $headers = ['Accept' => 'application/json'];

    if ($bearer !== null) {
        $headers['Authorization'] = 'Bearer '.$bearer;
    }

    return $testCase->withHeaders($headers)->post('/mcp', ['jsonrpc' => '2.0', 'method' => 'tools/list', 'id' => 1]);
}

/**
 * A real token through consent and the token endpoint.
 *
 * @return array{access_token: string, grant: GrantRecord, client: Client}
 */
function mcpAccessToken(AuthorizeFlowTestCase $testCase): array
{
    $client = $testCase->createClient();
    ['code' => $code, 'user' => $user] = $testCase->obtainAuthorizationCode($client);
    $response = $testCase->withHeaders(['Accept' => 'application/json'])
        ->post('/oauth/token', $testCase->codeExchange($client, $code))
        ->assertOk();

    return [
        'access_token' => (string) $response->json('access_token'),
        'grant' => $testCase->grantStore()->activeFor((string) $client->getKey(), (string) $user->getKey()),
        'client' => $client,
    ];
}

/**
 * A token signed with the server's key but with the expiry and scopes a test
 * needs; its row is copied from a real token so the binding stays valid.
 *
 * @param  list<string>  $scopes
 */
function signedAccessTokenLike(string $realToken, array $scopes, CarbonImmutable $expiresAt): string
{
    $realTokenId = (string) Passport::token()->newQuery()->value('id');
    $realRow = (array) DB::table('oauth_access_tokens')->where('id', $realTokenId)->first();
    $tokenId = Str::random(80);
    DB::table('oauth_access_tokens')->insert([...$realRow, 'id' => $tokenId, 'scopes' => json_encode($scopes), 'expires_at' => $expiresAt]);

    $accessToken = new AccessToken((string) $realRow['user_id'], array_map(static fn (string $scope): Scope => new Scope($scope), $scopes), new BridgeClient((string) $realRow['client_id']));
    $accessToken->setIdentifier($tokenId);
    $accessToken->setExpiryDateTime($expiresAt->toDateTimeImmutable());
    $accessToken->setPrivateKey(new CryptKey((string) config('passport.private_key'), null, false));

    return $accessToken->toString();
}

/**
 * A token signed with the server's key but without league's `scopes` claim,
 * or with it null: only a holder of the private key can make one, and the
 * door must still refuse it as invalid rather than fail (#22 review N1).
 */
function signedAccessTokenWithoutScopes(bool $hasNullScopesClaim): string
{
    $realTokenId = (string) Passport::token()->newQuery()->value('id');
    $realRow = (array) DB::table('oauth_access_tokens')->where('id', $realTokenId)->first();
    $tokenId = Str::random(80);
    DB::table('oauth_access_tokens')->insert([...$realRow, 'id' => $tokenId, 'scopes' => '[]']);

    $jwtConfiguration = Configuration::forAsymmetricSigner(
        new Sha256,
        InMemory::plainText((string) config('passport.private_key')),
        InMemory::plainText((string) config('passport.public_key')),
    );
    $now = CarbonImmutable::now()->toDateTimeImmutable();
    $builder = $jwtConfiguration->builder()
        ->permittedFor((string) $realRow['client_id'])
        ->identifiedBy($tokenId)
        ->issuedAt($now)
        ->canOnlyBeUsedAfter($now)
        ->expiresAt($now->modify('+1 hour'))
        ->relatedTo((string) $realRow['user_id']);

    if ($hasNullScopesClaim) {
        $builder = $builder->withClaim('scopes', null);
    }

    return $builder->getToken($jwtConfiguration->signer(), $jwtConfiguration->signingKey())->toString();
}

function refusedChallenge(string $description): string
{
    return 'Bearer realm="mcp", error="invalid_token", error_description="'.$description.'", resource_metadata="'.RESOURCE_METADATA_URL.'"';
}

// --- OAuth off: API keys exactly as before (S5, S6) -----------------------------

it('with OAuth off keeps the plain challenge and the API-key door (S5, S6)', function (?string $bearer, int $status): void {
    config()->set('mcp-oauth.enabled', false);
    app()->instance(ApiKeyDoor::class, new FakeApiKeyDoor(['ak_valid']));
    app()->instance(McpCredentialBinder::class, $binder = new FakeMcpCredentialBinder);
    McpOAuthRoutes::register();
    registerMcpRoute();

    $response = callMcp($this, $bearer)->assertStatus($status);

    if ($status === 401) {
        $response->assertHeader('WWW-Authenticate', OFF_CHALLENGE);
    } else {
        expect($binder->boundApiKeys)->toHaveCount(1);
    }
})->with([
    'no credentials' => [null, 401],
    'a token that is no API key: an unknown key, as before' => ['eyJhbGciOiJSUzI1NiJ9.e30.c2ln', 401],
    'an unknown API key' => ['ak_unknown', 401],
    'a valid API key' => ['ak_valid', 200],
]);

// --- OAuth on: both doors ---------------------------------------------------------

it('asks for credentials with the resource metadata and the scope, without an error code (S5)', function (): void {
    $this->enableOAuth();
    McpOAuthRoutes::register();
    registerMcpRoute();

    callMcp($this, null)
        ->assertStatus(401)
        ->assertHeader('WWW-Authenticate', 'Bearer realm="mcp", scope="mcp:use", resource_metadata="'.RESOURCE_METADATA_URL.'"')
        ->assertExactJson(['message' => 'Authentication required.']);
});

it('lets a valid OAuth token in and binds its grant', function (): void {
    $this->enableOAuth();
    McpOAuthRoutes::register();
    registerMcpRoute();
    ['access_token' => $accessToken, 'grant' => $grant] = mcpAccessToken($this);

    callMcp($this, $accessToken)
        ->assertOk()
        ->assertJsonPath('credential', GrantRecord::class)
        ->assertHeaderMissing('WWW-Authenticate');

    expect(app(McpCredentialBinder::class)->boundGrants)->toHaveCount(1)
        ->and(app(McpCredentialBinder::class)->boundGrants[0]->id)->toBe($grant->id)
        ->and(app(GrantAuthorizer::class)->authorizedGrants)->toHaveCount(1);
});

it('keeps API keys working with OAuth on', function (): void {
    $this->enableOAuth();
    McpOAuthRoutes::register();
    registerMcpRoute();

    callMcp($this, 'ak_valid')->assertOk();
    callMcp($this, 'ak_unknown')->assertStatus(401)->assertHeader('WWW-Authenticate', 'Bearer realm="mcp", error="invalid_token", resource_metadata="'.RESOURCE_METADATA_URL.'"');
});

it('answers 503 for an OAuth token while the keys are missing, and still takes API keys (S8)', function (): void {
    $this->enableOAuth();
    config()->set('passport.private_key', '');
    config()->set('passport.public_key', '');
    $missingKeyDirectory = sys_get_temp_dir().'/mcp-oauth-door-no-keys-'.uniqid('', true);
    mkdir($missingKeyDirectory, 0700);
    Passport::loadKeysFrom($missingKeyDirectory);
    McpOAuthRoutes::register();
    registerMcpRoute();

    callMcp($this, 'eyJhbGciOiJSUzI1NiJ9.e30.c2ln')
        ->assertStatus(503)
        ->assertHeaderMissing('WWW-Authenticate')
        ->assertExactJson(['error' => 'temporarily_unavailable', 'error_description' => 'OAuth is unavailable because Passport keys are missing.']);
    callMcp($this, 'ak_valid')->assertOk();
});

// --- The use-time checks (design §8.5) --------------------------------------------

it('refuses a token with a description that says why (S60)', function (Closure $tokenOf, string $description): void {
    $this->enableOAuth();
    McpOAuthRoutes::register();
    registerMcpRoute();
    $token = $tokenOf($this, mcpAccessToken($this));

    callMcp($this, $token)
        ->assertStatus(401)
        ->assertHeader('WWW-Authenticate', refusedChallenge($description))
        ->assertJsonPath('error', 'invalid_token');

    expect(app(McpCredentialBinder::class)->boundGrants)->toBe([]);
})->with([
    'garbage' => [static fn ($testCase, array $issued): string => 'not-a-jwt', 'The access token is not valid.'],
    'expired' => [static fn ($testCase, array $issued): string => signedAccessTokenLike($issued['access_token'], ['mcp:use'], CarbonImmutable::now()->subMinute()), 'The access token expired.'],
    'revoked' => [static function ($testCase, array $issued): string {
        DB::table('oauth_access_tokens')->update(['revoked' => true]);

        return $issued['access_token'];
    }, 'The access token was revoked.'],
    'purged' => [static function ($testCase, array $issued): string {
        DB::table('oauth_access_tokens')->delete();

        return $issued['access_token'];
    }, 'The access token was revoked.'],
    'another audience (S61)' => [static function ($testCase, array $issued): string {
        DB::table('oauth_access_tokens')->update(['audience' => 'https://elsewhere.example/mcp']);

        return $issued['access_token'];
    }, 'The access token is not valid.'],
    'no audience (S61)' => [static function ($testCase, array $issued): string {
        DB::table('oauth_access_tokens')->update(['audience' => null]);

        return $issued['access_token'];
    }, 'The access token is not valid.'],
    'a revoked client (S62)' => [static function ($testCase, array $issued): string {
        $issued['client']->forceFill(['revoked' => true])->save();

        return $issued['access_token'];
    }, 'The access token was revoked.'],
    'a client the package did not register' => [static function ($testCase, array $issued): string {
        OAuthClientMetadata::query()->where('client_id', $issued['client']->getKey())->delete();

        return $issued['access_token'];
    }, 'The access token was revoked.'],
    'a blocked redirect host (S37)' => [static function ($testCase, array $issued): string {
        OAuthBlockedRedirectHost::query()->create(['host' => 'app.example']);

        return $issued['access_token'];
    }, 'The access token was revoked.'],
    'no binding (S63)' => [static function ($testCase, array $issued): string {
        DB::table('oauth_access_tokens')->update(['api_key_id' => null]);

        return $issued['access_token'];
    }, 'The access token is not valid.'],
    'bound to another grant (S63)' => [static function ($testCase, array $issued): string {
        DB::table('oauth_access_tokens')->update(['api_key_id' => '0195f0a0-0000-7000-8000-0000000000d4']);

        return $issued['access_token'];
    }, 'The access token is not valid.'],
    'a revoked grant, token row untouched (S65)' => [static function ($testCase, array $issued): string {
        $testCase->grantStore()->revoke($issued['grant']->id, null, RevocationReason::User);

        return $issued['access_token'];
    }, 'The access token was revoked.'],
    'scopes other than mcp:use' => [static fn ($testCase, array $issued): string => signedAccessTokenLike($issued['access_token'], ['mcp:use', 'admin'], CarbonImmutable::now()->addHour()), 'The access token is not valid.'],
    'no scopes claim' => [static fn (): string => signedAccessTokenWithoutScopes(false), 'The access token is not valid.'],
    'a null scopes claim' => [static fn (): string => signedAccessTokenWithoutScopes(true), 'The access token is not valid.'],
]);

it('validates the Bearer of the request it is given, not the current one (#22 review N4)', function (): void {
    $this->enableOAuth();
    McpOAuthRoutes::register();
    ['access_token' => $accessToken] = mcpAccessToken($this);
    $requestWith = static fn (string $bearer): Request => Request::create('/mcp', 'POST', server: ['HTTP_AUTHORIZATION' => 'Bearer '.$bearer]);
    $authenticator = app(AccessTokenAuthenticator::class);

    app()->instance('request', $requestWith($accessToken));

    expect($authenticator->authenticate($requestWith('not-a-token')))->toBeInstanceOf(AuthorizationDecision::class);

    app()->instance('request', $requestWith('not-a-token'));

    expect($authenticator->authenticate($requestWith($accessToken)))->toBeInstanceOf(GrantRecord::class);
});

it('renders the product\'s refusal: 403 insufficient_scope or 401 invalid_token', function (AuthorizationDecision $decision, int $status, string $challenge): void {
    $this->enableOAuth();
    app()->instance(GrantAuthorizer::class, new FakeGrantAuthorizer($decision));
    McpOAuthRoutes::register();
    registerMcpRoute();
    ['access_token' => $accessToken] = mcpAccessToken($this);

    callMcp($this, $accessToken)
        ->assertStatus($status)
        ->assertHeader('WWW-Authenticate', $challenge)
        ->assertExactJson(['error' => $decision->error, 'error_description' => $decision->description]);
})->with([
    'insufficient scope' => [AuthorizationDecision::insufficientScope('mcp:write', 'Writing needs mcp:write.'), 403, 'Bearer realm="mcp", error="insufficient_scope", error_description="Writing needs mcp:write.", scope="mcp:write", resource_metadata="'.RESOURCE_METADATA_URL.'"'],
    'owner lost access' => [AuthorizationDecision::invalidToken('The owner no longer holds this grant.'), 401, 'Bearer realm="mcp", error="invalid_token", error_description="The owner no longer holds this grant.", resource_metadata="'.RESOURCE_METADATA_URL.'"'],
    'a description with quotes (RFC 6750 §3)' => [AuthorizationDecision::invalidToken('Ask the "owner" \\ admin.'), 401, 'Bearer realm="mcp", error="invalid_token", error_description="Ask the \'owner\' \' admin.", resource_metadata="'.RESOURCE_METADATA_URL.'"'],
]);

// --- The failure brake (S74) --------------------------------------------------------

it('answers 429 before reading the credential once an address has failed too often (S74)', function (?string $failingBearer): void {
    $this->enableOAuth();
    app()->instance(ApiKeyDoor::class, new FakeApiKeyDoor(['ak_valid'], ['ak_forbidden']));
    config()->set('mcp-oauth.mcp_auth_failures_per_minute', 3);
    McpOAuthRoutes::register();
    registerMcpRoute();

    foreach (range(1, 3) as $attempt) {
        expect(callMcp($this, $failingBearer)->getStatusCode())->toBeIn([401, 403]);
    }

    $brakeResponse = callMcp($this, 'ak_valid')
        ->assertStatus(429)
        ->assertExactJson(['error' => 'temporarily_unavailable', 'error_description' => 'Too many failed attempts. Try again later.']);

    // The key the design names: one counter per address, whatever the credential.
    expect(RateLimiter::attempts('mcp-auth-failures:127.0.0.1'))->toBe(3)
        ->and((int) $brakeResponse->headers->get('Retry-After'))->toBeGreaterThan(0)
        ->and(app(ApiKeyDoor::class)->authenticatedBearers)->not->toContain('ak_valid');
})->with([
    'unknown API keys (the product\'s 401)' => ['ak_unknown'],
    'forbidden API keys (the product\'s 403)' => ['ak_forbidden'],
    'no credentials' => [null],
    'refused OAuth tokens' => ['not-a-jwt'],
]);

it('does not count a successful call as a failure', function (): void {
    $this->enableOAuth();
    config()->set('mcp-oauth.mcp_auth_failures_per_minute', 2);
    McpOAuthRoutes::register();
    registerMcpRoute();

    foreach (range(1, 4) as $attempt) {
        callMcp($this, 'ak_valid')->assertOk();
    }
});

it('answers a Bearer with no token like no credentials', function (): void {
    $this->enableOAuth();
    McpOAuthRoutes::register();
    registerMcpRoute();

    $this->withHeaders(['Accept' => 'application/json', 'Authorization' => 'Bearer '])
        ->post('/mcp', ['jsonrpc' => '2.0', 'method' => 'tools/list', 'id' => 1])
        ->assertStatus(401)
        ->assertHeader('WWW-Authenticate', 'Bearer realm="mcp", scope="mcp:use", resource_metadata="'.RESOURCE_METADATA_URL.'"');
});

it('with OAuth off takes any Bearer the product accepts, API-key-shaped or not', function (): void {
    config()->set('mcp-oauth.enabled', false);
    app()->instance(ApiKeyDoor::class, new FakeApiKeyDoor(['legacy-opaque-key']));
    app()->instance(McpCredentialBinder::class, $binder = new FakeMcpCredentialBinder);
    McpOAuthRoutes::register();
    registerMcpRoute();

    callMcp($this, 'legacy-opaque-key')->assertOk();

    expect($binder->boundApiKeys)->toHaveCount(1);
});

it('names insufficient_scope when the product refuses an API key with 403', function (): void {
    $this->enableOAuth();
    app()->instance(ApiKeyDoor::class, new FakeApiKeyDoor([], ['ak_forbidden']));
    McpOAuthRoutes::register();
    registerMcpRoute();

    callMcp($this, 'ak_forbidden')
        ->assertStatus(403)
        ->assertHeader('WWW-Authenticate', 'Bearer realm="mcp", error="insufficient_scope", resource_metadata="'.RESOURCE_METADATA_URL.'"');
});

it('judges the wire scopes as a set: repeated mcp:use is fine, none is not', function (array $scopes, int $status): void {
    $this->enableOAuth();
    McpOAuthRoutes::register();
    registerMcpRoute();
    $issued = mcpAccessToken($this);

    callMcp($this, signedAccessTokenLike($issued['access_token'], $scopes, CarbonImmutable::now()->addHour()))->assertStatus($status);
})->with([
    'mcp:use twice' => [['mcp:use', 'mcp:use'], 200],
    'no scope' => [[], 401],
]);

// --- A browser session is never a credential (S73) ------------------------------

it('refuses a signed-in browser session without a Bearer, even on a route inside web (S73)', function (bool $isInsideWeb): void {
    $this->enableOAuth();
    McpOAuthRoutes::register();
    $middleware = [McpChallengeMiddleware::class, McpBearerDoorMiddleware::class];
    Route::post('mcp', static fn (): string => 'reached the server')
        ->middleware($isInsideWeb ? ['web', ...$middleware] : $middleware);

    // The same group without the door does see the signed-in user: the session is live.
    Route::post('session-check', static fn (Request $request): JsonResponse => new JsonResponse(['isSignedIn' => $request->user() !== null]))
        ->middleware($isInsideWeb ? ['web'] : []);
    $user = $this->createUser();

    $this->actingAs($user)->postJson('/session-check')->assertExactJson(['isSignedIn' => true]);

    $response = $this->actingAs($user)->postJson('/mcp', ['jsonrpc' => '2.0', 'method' => 'tools/list', 'id' => 1]);

    $response->assertUnauthorized()
        ->assertHeader('WWW-Authenticate', 'Bearer realm="mcp", scope="mcp:use", resource_metadata="'.RESOURCE_METADATA_URL.'"');

    expect(app(McpCredentialBinder::class)->boundApiKeys)->toBe([])
        ->and(app(McpCredentialBinder::class)->boundGrants)->toBe([]);
})->with([
    'outside web' => [false],
    'inside web' => [true],
]);
