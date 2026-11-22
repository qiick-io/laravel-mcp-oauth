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

it('accepts digit-string TTL overrides from raw env-shaped config', function (): void {
    config([
        'mcp-oauth.access_token_ttl_minutes' => '90',
        'mcp-oauth.refresh_token_ttl_days' => '14',
        'mcp-oauth.auth_code_ttl_minutes' => '8',
    ]);

    (new McpOAuthServiceProvider($this->app))->boot();

    expect(CarbonInterval::instance(Passport::tokensExpireIn())->totalMinutes)->toBe(90.0)
        ->and(CarbonInterval::instance(Passport::refreshTokensExpireIn())->totalDays)->toBe(14.0);
});

dataset('boot_rejected_ttl_config', [
    'negative int' => ['access_token_ttl_minutes', -5],
    'zero' => ['access_token_ttl_minutes', 0],
    'non-numeric' => ['refresh_token_ttl_days', 'nope'],
    'float string' => ['access_token_ttl_minutes', '1.5'],
    'scientific' => ['access_token_ttl_minutes', '1e3'],
    'leading plus' => ['access_token_ttl_minutes', '+60'],
    'float value' => ['access_token_ttl_minutes', 1.5],
    'auth code over max' => ['auth_code_ttl_minutes', BoundedPositiveInt::AUTH_CODE_TTL_MINUTES_MAX + 1],
    'access over max' => ['access_token_ttl_minutes', BoundedPositiveInt::ACCESS_TOKEN_TTL_MINUTES_MAX + 1],
    'refresh over max' => ['refresh_token_ttl_days', BoundedPositiveInt::REFRESH_TOKEN_TTL_DAYS_MAX + 1],
]);

it('rejects invalid TTL config at boot', function (string $configKey, mixed $value): void {
    config(["mcp-oauth.{$configKey}" => $value]);

    expect(fn () => (new McpOAuthServiceProvider($this->app))->boot())
        ->toThrow(InvalidMcpOAuthConfigException::class, $configKey);
})->with('boot_rejected_ttl_config');
