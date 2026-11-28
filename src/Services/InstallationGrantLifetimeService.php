<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Services;

use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Support\Facades\Date;
use Qiick\McpOAuth\Data\GrantRecord;
use Qiick\McpOAuth\Internal\BoundedPositiveInt;

/**
 * Enforces the original consent's absolute deadline through every rotation.
 *
 * @internal
 */
final class InstallationGrantLifetimeService
{
    public static function maximumAgeDays(ConfigRepository $config): int
    {
        $key = 'companion.grant_max_age_days';
        $companion = $config->get('mcp-oauth.companion', []);
        $configuredAge = is_array($companion) ? $config->get('mcp-oauth.'.$key, 180) : null;

        return BoundedPositiveInt::require($configuredAge, $key, BoundedPositiveInt::COMPANION_GRANT_AGE_DAYS_MAX);
    }

    public static function hasExpired(GrantRecord $grant, ConfigRepository $config): bool
    {
        if ($grant->installation === null) {
            return false;
        }

        $maximumAgeSeconds = self::maximumAgeDays($config) * 86_400;

        return $grant->authorizedAt === null
            || $grant->authorizedAt->getTimestamp() + $maximumAgeSeconds <= Date::now()->getTimestamp();
    }
}
