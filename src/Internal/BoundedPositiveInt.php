<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Internal;

use Qiick\McpOAuth\Exceptions\InvalidMcpOAuthConfigException;

/**
 * Fail-closed positive integers for mcp-oauth TTL keys (design §6).
 *
 * Documented maxima keep a typo’d env from issuing near-permanent tokens
 * or over-long auth codes. Invalid values throw; they are never floored
 * or replaced with a default.
 */
final class BoundedPositiveInt
{
    /** Access tokens stay short-lived; one day is the hard ceiling. */
    public const int ACCESS_TOKEN_TTL_MINUTES_MAX = 1_440;

    /** Refresh tokens may last up to one year. */
    public const int REFRESH_TOKEN_TTL_DAYS_MAX = 365;

    /**
     * Auth codes match Passport / league’s PT10M default and must not live longer.
     */
    public const int AUTH_CODE_TTL_MINUTES_MAX = 10;

    /** Per-minute rate limiter ceilings (register / token). */
    public const int RATE_LIMIT_PER_MINUTE_MAX = 10_000;

    /** Hard ceiling for non-revoked Passport clients (DCR global cap). */
    public const int REGISTRATIONS_GLOBAL_CAP_MAX = 100_000;

    /**
     * Accepts a PHP int in range, or a string of ASCII digits only (no sign,
     * spaces, decimal point, or exponent). Never casts float / scientific
     * env strings the way `(int) env(...)` would.
     *
     * @throws InvalidMcpOAuthConfigException
     */
    public static function require(mixed $configuredValue, string $configKey, int $maximum): int
    {
        if (is_int($configuredValue)) {
            $integerValue = $configuredValue;
        } elseif (is_string($configuredValue) && preg_match('/^\d+$/', $configuredValue) === 1) {
            $integerValue = (int) $configuredValue;
        } else {
            throw InvalidMcpOAuthConfigException::invalidInteger($configKey, $maximum);
        }

        if ($integerValue < 1 || $integerValue > $maximum) {
            throw InvalidMcpOAuthConfigException::outOfRange($configKey, $integerValue, $maximum);
        }

        return $integerValue;
    }
}
