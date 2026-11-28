<?php

declare(strict_types=1);

use Illuminate\Config\Repository;
use Illuminate\Support\Facades\Date;
use Qiick\McpOAuth\Data\GrantInstallationData;
use Qiick\McpOAuth\Data\GrantRecord;
use Qiick\McpOAuth\Exceptions\InvalidMcpOAuthConfigException;
use Qiick\McpOAuth\Services\InstallationGrantLifetimeService;

it('uses the absolute age from configuration and supplies the shipped default', function (array $settings, int $expectedDays): void {
    expect(InstallationGrantLifetimeService::maximumAgeDays(new Repository(['mcp-oauth' => $settings])))->toBe($expectedDays);
})->with([
    'older config' => [[], 180],
    'missing age' => [['companion' => []], 180],
    'explicit age' => [['companion' => ['grant_max_age_days' => '7']], 7],
]);

it('reports the key of an invalid absolute age configuration', function (mixed $companionSettings): void {
    $config = new Repository(['mcp-oauth' => ['companion' => $companionSettings]]);

    expect(fn () => InstallationGrantLifetimeService::maximumAgeDays($config))
        ->toThrow(InvalidMcpOAuthConfigException::class, 'companion.grant_max_age_days');
})->with([
    'invalid parent' => ['enabled'],
    'explicit null age' => [['grant_max_age_days' => null]],
    'zero days' => [['grant_max_age_days' => 0]],
    'above the limit' => [['grant_max_age_days' => 3651]],
]);

it('expires installations at the original consent deadline', function (?string $consentTime, bool $isInstallation, bool $hasExpired): void {
    $now = new DateTimeImmutable('2026-11-28T12:00:00+00:00');
    Date::setTestNow($now);

    try {
        $grant = new GrantRecord(
            id: 'grant',
            clientId: 'client',
            userIdentifier: 'user',
            revoked: false,
            scopes: [],
            authorizedAt: $consentTime === null ? null : new DateTimeImmutable($consentTime),
            lastUsedAt: null,
            installation: $isInstallation ? new GrantInstallationData('installation', 'thumbprint') : null,
        );
        $config = new Repository(['mcp-oauth' => ['companion' => ['grant_max_age_days' => 1]]]);

        expect(InstallationGrantLifetimeService::hasExpired($grant, $config))->toBe($hasExpired);
    } finally {
        Date::setTestNow();
    }
})->with([
    'one second remaining' => ['2026-11-27T12:00:01+00:00', true, false],
    'exactly at the deadline' => ['2026-11-27T12:00:00+00:00', true, true],
    'missing installation consent' => [null, true, true],
    'legacy grant' => [null, false, false],
]);
