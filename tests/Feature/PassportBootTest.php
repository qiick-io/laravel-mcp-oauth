<?php

declare(strict_types=1);

use Carbon\CarbonInterval;
use Laravel\Passport\Passport;
use Qiick\McpOAuth\Exceptions\InvalidMcpOAuthConfigException;
use Qiick\McpOAuth\Internal\BoundedPositiveInt;
use Qiick\McpOAuth\McpOAuthServiceProvider;

/**
 * S4 / design §5.6: Passport routes stay off, device grant stays off, TTLs
 * follow mcp-oauth config and fail closed on invalid values (design §6).
 */
it('S4: always ignores Passport routes so Passport never registers /oauth/*', function (): void {
    expect(Passport::$registersRoutes)->toBeFalse();
});

it('S19: device code grant stays disabled', function (): void {
    expect(Passport::$deviceCodeGrantEnabled)->toBeFalse();
});

it('applies access and refresh token TTLs from mcp-oauth config', function (): void {
    expect(CarbonInterval::instance(Passport::tokensExpireIn())->totalMinutes)->toBe(60.0)
        ->and(CarbonInterval::instance(Passport::refreshTokensExpireIn())->totalDays)->toBe(30.0);
});

it('honours overridden access and refresh TTLs from config', function (): void {
    config([
        'mcp-oauth.access_token_ttl_minutes' => 15,
        'mcp-oauth.refresh_token_ttl_days' => 7,
        'mcp-oauth.auth_code_ttl_minutes' => 5,
    ]);

    (new McpOAuthServiceProvider($this->app))->boot();

    expect(CarbonInterval::instance(Passport::tokensExpireIn())->totalMinutes)->toBe(15.0)
        ->and(CarbonInterval::instance(Passport::refreshTokensExpireIn())->totalDays)->toBe(7.0);
});

it('rejects negative access token TTLs at boot', function (): void {
    config(['mcp-oauth.access_token_ttl_minutes' => -5]);

    expect(fn () => (new McpOAuthServiceProvider($this->app))->boot())
        ->toThrow(InvalidMcpOAuthConfigException::class, 'access_token_ttl_minutes');
});

it('rejects zero TTLs at boot (env cast typo)', function (): void {
    config([
        'mcp-oauth.access_token_ttl_minutes' => 0,
        'mcp-oauth.refresh_token_ttl_days' => 30,
        'mcp-oauth.auth_code_ttl_minutes' => 10,
    ]);

    expect(fn () => (new McpOAuthServiceProvider($this->app))->boot())
        ->toThrow(InvalidMcpOAuthConfigException::class, 'access_token_ttl_minutes');
});

it('rejects non-numeric refresh token TTLs at boot', function (): void {
    config(['mcp-oauth.refresh_token_ttl_days' => 'nope']);

    expect(fn () => (new McpOAuthServiceProvider($this->app))->boot())
        ->toThrow(InvalidMcpOAuthConfigException::class, 'refresh_token_ttl_days');
});

it('rejects auth code TTLs above the documented maximum at boot', function (): void {
    config(['mcp-oauth.auth_code_ttl_minutes' => BoundedPositiveInt::AUTH_CODE_TTL_MINUTES_MAX + 1]);

    expect(fn () => (new McpOAuthServiceProvider($this->app))->boot())
        ->toThrow(InvalidMcpOAuthConfigException::class, 'auth_code_ttl_minutes');
});

it('rejects access token TTLs above the documented maximum at boot', function (): void {
    config(['mcp-oauth.access_token_ttl_minutes' => BoundedPositiveInt::ACCESS_TOKEN_TTL_MINUTES_MAX + 1]);

    expect(fn () => (new McpOAuthServiceProvider($this->app))->boot())
        ->toThrow(InvalidMcpOAuthConfigException::class, 'access_token_ttl_minutes');
});

it('rejects refresh token TTLs above the documented maximum at boot', function (): void {
    config(['mcp-oauth.refresh_token_ttl_days' => BoundedPositiveInt::REFRESH_TOKEN_TTL_DAYS_MAX + 1]);

    expect(fn () => (new McpOAuthServiceProvider($this->app))->boot())
        ->toThrow(InvalidMcpOAuthConfigException::class, 'refresh_token_ttl_days');
});

it('rejects float TTL values at boot', function (): void {
    config(['mcp-oauth.access_token_ttl_minutes' => 1.5]);

    expect(fn () => (new McpOAuthServiceProvider($this->app))->boot())
        ->toThrow(InvalidMcpOAuthConfigException::class, 'access_token_ttl_minutes');
});
