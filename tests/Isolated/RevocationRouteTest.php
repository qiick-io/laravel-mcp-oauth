<?php

declare(strict_types=1);

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Hash;
use Illuminate\Testing\TestResponse;
use Laravel\Passport\Client;
use Qiick\McpOAuth\Data\RevocationReason;
use Qiick\McpOAuth\Events\McpRefreshTokenReused;
use Qiick\McpOAuth\Events\McpTokenRevoked;
use Qiick\McpOAuth\McpOAuthRoutes;
use Qiick\McpOAuth\Tests\Support\AuthorizeFlowTestCase;

uses(AuthorizeFlowTestCase::class);

/**
 * `POST oauth/revoke` (RFC 7009; standards review Resolved #5 and S1, with
 * the 2026-11-23 decision on access tokens):
 *
 * - a refresh token revokes its family and the grant (RevocationReason::Client);
 * - an access token revokes itself and the refresh tokens issued with it, not
 *   the grant;
 * - always 200 for a token that is unknown, already dead or another client's;
 * - a revoked refresh token presented later is refused without being read as
 *   reuse.
 */
const REVOKE_INVALID_CLIENT_BODY = [
    'error' => 'invalid_client',
    'error_description' => 'Client authentication failed.',
];

const REVOKE_INVALID_REQUEST_BODY = [
    'error' => 'invalid_request',
    'error_description' => 'The request is missing a required parameter, repeats a parameter or is otherwise malformed.',
];

/**
 * @param  array<string, mixed>  $parameters
 * @param  array<string, string>  $headers
 */
function postRevoke(AuthorizeFlowTestCase $testCase, array $parameters, array $headers = []): TestResponse
{
    return $testCase->withHeaders(['Accept' => 'application/json', ...$headers])->post('/oauth/revoke', $parameters);
}

/**
 * @return array{access_token: string, refresh_token: string, user_id: string}
 */
function tokensFor(AuthorizeFlowTestCase $testCase, Client $client): array
{
    ['code' => $code, 'user' => $user] = $testCase->obtainAuthorizationCode($client);
    $response = $testCase->withHeaders(['Accept' => 'application/json'])
        ->post('/oauth/token', $testCase->codeExchange($client, $code))
        ->assertOk();

    return [
        'access_token' => (string) $response->json('access_token'),
        'refresh_token' => (string) $response->json('refresh_token'),
        'user_id' => (string) $user->getKey(),
    ];
}

function refreshWith(AuthorizeFlowTestCase $testCase, Client $client, string $refreshToken): TestResponse
{
    return $testCase->withHeaders(['Accept' => 'application/json'])->post('/oauth/token', [
        'grant_type' => 'refresh_token',
        'client_id' => (string) $client->getKey(),
        'refresh_token' => $refreshToken,
        'resource' => AuthorizeFlowTestCase::RESOURCE,
    ]);
}

// --- Route (design §4.2) -------------------------------------------------------

it('with OAuth off matches an unregistered /oauth/revoke on every method', function (string $method): void {
    config()->set('app.debug', false);
    config()->set('mcp-oauth.enabled', false);
    $unregisteredResponse = $this->call($method, '/oauth/revoke', ['token' => 'x'], server: ['HTTP_ACCEPT' => 'application/json']);

    McpOAuthRoutes::register();

    $gatedResponse = $this->call($method, '/oauth/revoke', ['token' => 'x'], server: ['HTTP_ACCEPT' => 'application/json']);

    expect($gatedResponse->getStatusCode())->toBe(404)
        ->and($gatedResponse->headers->get('Allow'))->toBe($unregisteredResponse->headers->get('Allow'))
        ->and($gatedResponse->getContent())->toBe($unregisteredResponse->getContent());
})->with(['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS']);

it('answers 405 with Allow: POST on other methods when OAuth is on', function (string $method): void {
    $this->enableOAuth();
    McpOAuthRoutes::register();

    $this->call($method, '/oauth/revoke')
        ->assertStatus(405)
        ->assertHeader('Allow', 'POST');
})->with(['GET', 'HEAD', 'PUT', 'PATCH', 'DELETE', 'OPTIONS']);

it('is named mcp.oauth.revoke, stateless and throttled with mcp-oauth-revoke', function (): void {
    $this->enableOAuth();
    McpOAuthRoutes::register();
    $route = app('router')->getRoutes()->getByName('mcp.oauth.revoke');

    expect($route)->not->toBeNull()
        ->and($route->uri())->toBe('oauth/revoke')
        ->and($route->gatherMiddleware())->toContain('throttle:mcp-oauth-revoke')
        ->and($route->gatherMiddleware())->not->toContain('web');
});

// --- Refresh tokens: family and grant (Resolved #5) --------------------------

it('revokes a refresh token with its family and grant', function (): void {
    Event::fake([McpTokenRevoked::class, McpRefreshTokenReused::class]);
    $this->enableOAuth();
    McpOAuthRoutes::register();
    $client = $this->createClient();
    $tokens = tokensFor($this, $client);
    $rotated = refreshWith($this, $client, $tokens['refresh_token'])->assertOk();
    $grant = $this->grantStore()->activeFor((string) $client->getKey(), $tokens['user_id']);

    $response = postRevoke($this, ['token' => (string) $rotated->json('refresh_token'), 'client_id' => (string) $client->getKey()]);

    $response->assertOk()->assertHeader('Cache-Control', 'no-store, private');
    expect($response->getContent())->toBe('')
        ->and(DB::table('oauth_access_tokens')->where('revoked', false)->count())->toBe(0)
        ->and(DB::table('oauth_refresh_tokens')->count())->toBe(0)
        ->and($this->grantStore()->find($grant->id)?->revoked)->toBeTrue()
        ->and(collect($this->grantStore()->revocations)->last())->toMatchArray([
            'grantId' => $grant->id,
            'reason' => RevocationReason::Client,
        ]);

    Event::assertDispatched(McpTokenRevoked::class, static fn (McpTokenRevoked $event): bool => $event->clientId === (string) $client->getKey()
        && $event->userIdentifier === $tokens['user_id']
        && $event->grantId === $grant->id
        && $event->tokenType === 'refresh_token'
        && $event->revokedTokenCount === 3);

    // Presented again, it is unknown: refused, never read as reuse.
    refreshWith($this, $client, (string) $rotated->json('refresh_token'))->assertStatus(400)->assertJsonPath('error', 'invalid_grant');
    Event::assertNotDispatched(McpRefreshTokenReused::class);
    expect(collect($this->grantStore()->revocations)->pluck('reason'))->not->toContain(RevocationReason::Reuse);
});

// --- Access tokens: the token and its refresh tokens, not the grant ---------

it('revokes an access token and its refresh token, but not the grant', function (): void {
    Event::fake([McpTokenRevoked::class, McpRefreshTokenReused::class]);
    $this->enableOAuth();
    McpOAuthRoutes::register();
    $client = $this->createClient();
    $tokens = tokensFor($this, $client);
    $grant = $this->grantStore()->activeFor((string) $client->getKey(), $tokens['user_id']);

    postRevoke($this, ['token' => $tokens['access_token'], 'token_type_hint' => 'access_token', 'client_id' => (string) $client->getKey()])
        ->assertOk();

    expect(DB::table('oauth_access_tokens')->where('revoked', false)->count())->toBe(0)
        ->and(DB::table('oauth_refresh_tokens')->count())->toBe(0)
        ->and($this->grantStore()->find($grant->id)?->revoked)->toBeFalse();

    Event::assertDispatched(McpTokenRevoked::class, static fn (McpTokenRevoked $event): bool => $event->tokenType === 'access_token'
        && $event->grantId === $grant->id
        && $event->revokedTokenCount === 2);

    // The refresh token issued with it is refused alone: no family, no reuse.
    refreshWith($this, $client, $tokens['refresh_token'])->assertStatus(400)->assertJsonPath('error', 'invalid_grant');
    Event::assertNotDispatched(McpRefreshTokenReused::class);
    expect($this->grantStore()->find($grant->id)?->revoked)->toBeFalse()
        ->and($this->grantStore()->revocations)->toBe([]);
});

it('ignores the token_type_hint when it is wrong', function (string $hint): void {
    $this->enableOAuth();
    McpOAuthRoutes::register();
    $client = $this->createClient();
    $tokens = tokensFor($this, $client);

    postRevoke($this, ['token' => $tokens['refresh_token'], 'token_type_hint' => $hint, 'client_id' => (string) $client->getKey()])
        ->assertOk();

    expect(DB::table('oauth_refresh_tokens')->count())->toBe(0);
})->with(['access_token', 'refresh_token', 'something_else']);

// --- Never an oracle (RFC 7009 §2.2) -----------------------------------------

it('answers 200 and changes nothing for an unknown, foreign or dead token', function (Closure $tokenOf): void {
    $this->enableOAuth();
    McpOAuthRoutes::register();
    $client = $this->createClient();
    $otherClient = $this->createClient();
    $tokens = tokensFor($this, $client);
    $token = $tokenOf($this, $client, $tokens);

    postRevoke($this, ['token' => $token, 'client_id' => (string) $otherClient->getKey()])
        ->assertOk();

    expect(DB::table('oauth_access_tokens')->where('revoked', false)->count())->toBe(1)
        ->and(DB::table('oauth_refresh_tokens')->count())->toBe(1);
})->with([
    'garbage' => [static fn ($testCase, Client $client, array $tokens): string => 'not-a-token'],
    'another client\'s refresh token' => [static fn ($testCase, Client $client, array $tokens): string => $tokens['refresh_token']],
    'another client\'s access token' => [static fn ($testCase, Client $client, array $tokens): string => $tokens['access_token']],
    'a forged JWT' => [static fn ($testCase, Client $client, array $tokens): string => implode('.', [
        rtrim(strtr(base64_encode('{"alg":"RS256","typ":"JWT"}'), '+/', '-_'), '='),
        rtrim(strtr(base64_encode('{"jti":"x","aud":"y"}'), '+/', '-_'), '='),
        'c2lnbmF0dXJl',
    ])],
]);

// --- Client authentication (RFC 7009 §2.1, RFC 6749 §2.3) --------------------

it('identifies a public client by client_id, in the body or HTTP Basic', function (string $source): void {
    $this->enableOAuth();
    McpOAuthRoutes::register();
    $client = $this->createClient();
    $tokens = tokensFor($this, $client);
    $parameters = ['token' => $tokens['refresh_token']];
    $headers = [];

    if ($source === 'body') {
        $parameters['client_id'] = (string) $client->getKey();
    } else {
        $headers['Authorization'] = 'Basic '.base64_encode($client->getKey().':');
    }

    postRevoke($this, $parameters, $headers)->assertOk();

    expect(DB::table('oauth_refresh_tokens')->count())->toBe(0);
})->with(['body', 'basic']);

it('requires the secret of a confidential client', function (array $credentials, int $status): void {
    $this->enableOAuth();
    McpOAuthRoutes::register();
    $client = $this->createClient();
    $tokens = tokensFor($this, $client);
    // Confidential from now on; the exchange above ran as a public client.
    $client->forceFill(['secret' => Hash::make('s3cret')])->save();
    $parameters = ['token' => $tokens['refresh_token']];
    $headers = [];

    if (isset($credentials['basic'])) {
        $headers['Authorization'] = 'Basic '.base64_encode($client->getKey().':'.$credentials['basic']);
    } else {
        $parameters['client_id'] = (string) $client->getKey();
        $parameters['client_secret'] = $credentials['post'] ?? null;
    }

    postRevoke($this, array_filter($parameters, static fn (mixed $value): bool => $value !== null), $headers)->assertStatus($status);

    expect(DB::table('oauth_refresh_tokens')->count())->toBe($status === 200 ? 0 : 1);
})->with([
    'client_secret_basic' => [['basic' => 's3cret'], 200],
    'client_secret_post' => [['post' => 's3cret'], 200],
    'wrong secret' => [['post' => 'wrong'], 401],
    'no secret' => [[], 401],
]);

it('refuses an unknown, malformed or revoked client as invalid_client', function (string $clientCase): void {
    $this->enableOAuth();
    McpOAuthRoutes::register();
    $client = $this->createClient(isRevoked: $clientCase === 'revoked');
    $clientId = match ($clientCase) {
        'unknown' => '0195f0a0-0000-7000-8000-000000000000',
        'not a uuid' => 'not-a-uuid',
        default => (string) $client->getKey(),
    };

    postRevoke($this, ['token' => 'x', 'client_id' => $clientId])
        ->assertStatus(401)
        ->assertExactJson(REVOKE_INVALID_CLIENT_BODY);
})->with(['unknown', 'not a uuid', 'revoked']);

it('challenges a client that authenticated with HTTP Basic', function (): void {
    $this->enableOAuth();
    McpOAuthRoutes::register();

    postRevoke($this, ['token' => 'x'], ['Authorization' => 'Basic '.base64_encode('0195f0a0-0000-7000-8000-000000000000:')])
        ->assertStatus(401)
        ->assertHeader('WWW-Authenticate', 'Basic realm="OAuth"');
});

it('refuses a request without a client or a token as invalid_request', function (array $parameters): void {
    $this->enableOAuth();
    McpOAuthRoutes::register();
    $client = $this->createClient();

    postRevoke($this, array_map(static fn (mixed $value): mixed => $value === 'CLIENT' ? (string) $client->getKey() : $value, $parameters))
        ->assertStatus(400)
        ->assertExactJson(REVOKE_INVALID_REQUEST_BODY);
})->with([
    'no token' => [['client_id' => 'CLIENT']],
    'repeated token' => [['client_id' => 'CLIENT', 'token' => ['a', 'b']]],
    'no client' => [['token' => 'x']],
    'repeated client' => [['client_id' => ['a', 'b'], 'token' => 'x']],
]);
