<?php

declare(strict_types=1);

use Illuminate\Cache\RateLimiting\Limit;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Support\Facades\Route;
use Qiick\McpOAuth\ClientThrottleKey;
use Qiick\McpOAuth\Exceptions\InvalidMcpOAuthConfigException;
use Qiick\McpOAuth\Internal\BoundedPositiveInt;
use Qiick\McpOAuth\McpOAuthServiceProvider;

/**
 * Design §5.6: DCR / authorize / token / revoke limiters — per-IP and
 * per-client, 429 with Retry-After.
 */
it('registers limiters for register, authorize, token and revoke', function (): void {
    foreach (['mcp-oauth-register', 'mcp-oauth-authorize', 'mcp-oauth-token', 'mcp-oauth-revoke'] as $limiterName) {
        expect(RateLimiter::limiter($limiterName))->toBeInstanceOf(Closure::class);
    }
});

it('applies IP limits by ClientThrottleKey and client limits when client_id is present', function (): void {
    $request = Request::create('/oauth/token', 'POST', [
        'client_id' => 'client-abc',
    ], server: ['REMOTE_ADDR' => '203.0.113.10']);

    /** @var Closure(Request): list<Limit> $tokenLimiter */
    $tokenLimiter = RateLimiter::limiter('mcp-oauth-token');
    $limits = $tokenLimiter($request);

    expect($limits)->toHaveCount(2)
        ->and($limits[0]->maxAttempts)->toBe(60)
        ->and($limits[0]->key)->toBe('token:ip:'.ClientThrottleKey::fromRequest($request))
        ->and($limits[1]->maxAttempts)->toBe(30)
        ->and($limits[1]->key)->toBe('token:client:client-abc');
});

it('uses HTTP Basic username as the per-client key when client_id is absent', function (): void {
    $request = Request::create('/oauth/token', 'POST', server: [
        'REMOTE_ADDR' => '203.0.113.10',
        'PHP_AUTH_USER' => 'basic-client',
        'PHP_AUTH_PW' => 'secret',
    ]);

    /** @var Closure(Request): list<Limit> $tokenLimiter */
    $tokenLimiter = RateLimiter::limiter('mcp-oauth-token');
    $limits = $tokenLimiter($request);

    expect($limits)->toHaveCount(2)
        ->and($limits[1]->key)->toBe('token:client:basic-client');
});

it('keys the per-client limit on the body or Basic client id, lower-cased, never the query', function (): void {
    /** @var Closure(Request): list<Limit> $tokenLimiter */
    $tokenLimiter = RateLimiter::limiter('mcp-oauth-token');

    $bodyRequest = Request::create('/oauth/token?client_id=random-'.uniqid(), 'POST', ['client_id' => 'ABC-Def'], server: ['REMOTE_ADDR' => '203.0.113.10']);
    $queryOnlyRequest = Request::create('/oauth/token?client_id=random-'.uniqid(), 'POST', server: ['REMOTE_ADDR' => '203.0.113.10']);
    $basicRequest = Request::create('/oauth/token?client_id=random', 'POST', server: [
        'REMOTE_ADDR' => '203.0.113.10',
        'PHP_AUTH_USER' => 'ABC-DEF',
        'PHP_AUTH_PW' => '',
    ]);

    expect($tokenLimiter($bodyRequest)[1]->key)->toBe('token:client:abc-def')
        ->and($tokenLimiter($queryOnlyRequest))->toHaveCount(1)
        ->and($tokenLimiter($basicRequest)[1]->key)->toBe('token:client:abc-def');
});

it('keeps DCR IP-only because registration has no client yet', function (): void {
    $request = Request::create('/oauth/register', 'POST', [
        'client_id' => 'should-be-ignored',
    ], server: ['REMOTE_ADDR' => '198.51.100.20']);

    /** @var Closure(Request): list<Limit> $registerLimiter */
    $registerLimiter = RateLimiter::limiter('mcp-oauth-register');
    $limits = $registerLimiter($request);

    expect($limits)->toHaveCount(1)
        ->and($limits[0]->maxAttempts)->toBe(10)
        ->and($limits[0]->key)->toBe('register:ip:'.ClientThrottleKey::fromRequest($request));
});

it('defaults authorize and revoke to prudent per-IP and per-client caps', function (): void {
    $request = Request::create('/oauth/authorize', 'GET', [
        'client_id' => 'client-xyz',
    ], server: ['REMOTE_ADDR' => '203.0.113.50']);

    /** @var Closure(Request): list<Limit> $authorizeLimiter */
    $authorizeLimiter = RateLimiter::limiter('mcp-oauth-authorize');
    /** @var Closure(Request): list<Limit> $revokeLimiter */
    $revokeLimiter = RateLimiter::limiter('mcp-oauth-revoke');

    expect($authorizeLimiter($request)[0]->maxAttempts)->toBe(30)
        ->and($authorizeLimiter($request)[1]->maxAttempts)->toBe(20)
        ->and($revokeLimiter($request)[0]->maxAttempts)->toBe(30)
        ->and($revokeLimiter($request)[1]->maxAttempts)->toBe(20);
});

it('answers 429 with Retry-After when a limiter is exceeded', function (): void {
    config([
        'mcp-oauth.token_requests_per_minute' => '2',
        'mcp-oauth.token_requests_per_client_per_minute' => '100',
    ]);

    (new McpOAuthServiceProvider($this->app))->boot();

    Route::post('/_mcp-oauth-test/token', static fn () => response('ok'))
        ->middleware('throttle:mcp-oauth-token');

    $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.99']);

    $this->post('/_mcp-oauth-test/token', ['client_id' => 'c1'])->assertOk();
    $this->post('/_mcp-oauth-test/token', ['client_id' => 'c1'])->assertOk();

    $this->post('/_mcp-oauth-test/token', ['client_id' => 'c1'])
        ->assertStatus(429)
        ->assertHeader('Retry-After')
        ->assertExactJson(['error' => 'temporarily_unavailable', 'error_description' => 'Too many requests. Try again later.']);
});

it('rejects invalid rate limit config at boot', function (): void {
    config(['mcp-oauth.authorize_requests_per_minute' => '1e2']);

    expect(fn () => (new McpOAuthServiceProvider($this->app))->boot())
        ->toThrow(InvalidMcpOAuthConfigException::class, 'authorize_requests_per_minute');

    config([
        'mcp-oauth.authorize_requests_per_minute' => '30',
        'mcp-oauth.revoke_requests_per_client_per_minute' => BoundedPositiveInt::RATE_LIMIT_PER_MINUTE_MAX + 1,
    ]);

    expect(fn () => (new McpOAuthServiceProvider($this->app))->boot())
        ->toThrow(InvalidMcpOAuthConfigException::class, 'revoke_requests_per_client_per_minute');
});

it('rejects non-digit mcp_auth_failures_per_minute at boot', function (): void {
    config(['mcp-oauth.mcp_auth_failures_per_minute' => '1e2']);

    expect(fn () => (new McpOAuthServiceProvider($this->app))->boot())
        ->toThrow(InvalidMcpOAuthConfigException::class, 'mcp_auth_failures_per_minute');
});
