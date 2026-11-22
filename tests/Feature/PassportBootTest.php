<?php

declare(strict_types=1);

use Carbon\CarbonInterval;
use Laravel\Passport\Passport;
use Qiick\McpOAuth\McpOAuthServiceProvider;

/**
 * S4 / design §5.6: Passport routes stay off, device grant stays off, TTLs
 * follow mcp-oauth config. Red-first gates for the Passport boot PR.
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
    ]);

    (new McpOAuthServiceProvider($this->app))->boot();

    expect(CarbonInterval::instance(Passport::tokensExpireIn())->totalMinutes)->toBe(15.0)
        ->and(CarbonInterval::instance(Passport::refreshTokensExpireIn())->totalDays)->toBe(7.0);
});
