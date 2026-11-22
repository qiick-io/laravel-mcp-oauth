<?php

declare(strict_types=1);

use Illuminate\Cache\RateLimiting\Limit;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\RateLimiter;
use Qiick\McpOAuth\ClientThrottleKey;
use Qiick\McpOAuth\Exceptions\InvalidMcpOAuthConfigException;
use Qiick\McpOAuth\Internal\BoundedPositiveInt;
use Qiick\McpOAuth\McpOAuthServiceProvider;

/**
 * Design §5.6: mcp-oauth-register / mcp-oauth-token are keyed by ClientThrottleKey.
 */
it('registers mcp-oauth-register and mcp-oauth-token limiters', function (): void {
    expect(RateLimiter::limiter('mcp-oauth-register'))->toBeInstanceOf(Closure::class)
        ->and(RateLimiter::limiter('mcp-oauth-token'))->toBeInstanceOf(Closure::class);
});

it('keys both limiters by ClientThrottleKey at the default per-minute caps', function (): void {
    $request = Request::create('/', 'POST', server: ['REMOTE_ADDR' => '203.0.113.10']);
    $expectedKey = ClientThrottleKey::fromRequest($request);

    /** @var Closure(Request): Limit $registerLimiter */
    $registerLimiter = RateLimiter::limiter('mcp-oauth-register');
    /** @var Closure(Request): Limit $tokenLimiter */
    $tokenLimiter = RateLimiter::limiter('mcp-oauth-token');

    $registerLimit = $registerLimiter($request);
    $tokenLimit = $tokenLimiter($request);

    expect($registerLimit)->toBeInstanceOf(Limit::class)
        ->and($registerLimit->maxAttempts)->toBe(10)
        ->and($registerLimit->decaySeconds)->toBe(60)
        ->and($registerLimit->key)->toBe($expectedKey)
        ->and($tokenLimit)->toBeInstanceOf(Limit::class)
        ->and($tokenLimit->maxAttempts)->toBe(60)
        ->and($tokenLimit->decaySeconds)->toBe(60)
        ->and($tokenLimit->key)->toBe($expectedKey);
});

it('honours overridden rate limit config after re-boot', function (): void {
    config([
        'mcp-oauth.registrations_per_minute' => '3',
        'mcp-oauth.token_requests_per_minute' => '7',
    ]);

    (new McpOAuthServiceProvider($this->app))->boot();

    $request = Request::create('/', 'POST', server: ['REMOTE_ADDR' => '198.51.100.20']);

    /** @var Closure(Request): Limit $registerLimiter */
    $registerLimiter = RateLimiter::limiter('mcp-oauth-register');
    /** @var Closure(Request): Limit $tokenLimiter */
    $tokenLimiter = RateLimiter::limiter('mcp-oauth-token');

    expect($registerLimiter($request)->maxAttempts)->toBe(3)
        ->and($tokenLimiter($request)->maxAttempts)->toBe(7)
        ->and($registerLimiter($request)->key)->toBe(ClientThrottleKey::fromRequest($request));
});

it('rejects invalid rate limit config at boot', function (): void {
    config(['mcp-oauth.registrations_per_minute' => '1e3']);

    expect(fn () => (new McpOAuthServiceProvider($this->app))->boot())
        ->toThrow(InvalidMcpOAuthConfigException::class, 'registrations_per_minute');

    config([
        'mcp-oauth.registrations_per_minute' => '10',
        'mcp-oauth.token_requests_per_minute' => BoundedPositiveInt::RATE_LIMIT_PER_MINUTE_MAX + 1,
    ]);

    expect(fn () => (new McpOAuthServiceProvider($this->app))->boot())
        ->toThrow(InvalidMcpOAuthConfigException::class, 'token_requests_per_minute');
});
