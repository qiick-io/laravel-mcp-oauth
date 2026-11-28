<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Internal;

use Qiick\McpOAuth\Exceptions\InvalidMcpOAuthConfigException;

/**
 * Fail-closed positive integers for every mcp-oauth integer key (design §6).
 *
 * Documented maxima keep a typo’d env from issuing near-permanent tokens
 * or over-long auth codes. Invalid values throw; they are never floored
 * or replaced with a default.
 *
 * @internal
 */
final class BoundedPositiveInt
{
    /** Access tokens stay short-lived; one day is the hard ceiling. */
    // PCOV has no line coverage for a class constant initializer.
    // @pest-mutate-ignore: IncrementInteger,DecrementInteger
    public const int ACCESS_TOKEN_TTL_MINUTES_MAX = 1_440;

    /** Clients blocked per chunk when a host is blocked: a chunk is one query and one loop. */
    // PCOV has no line coverage for a class constant initializer.
    // @pest-mutate-ignore: IncrementInteger,DecrementInteger
    public const int HOST_BLOCK_CHUNK_SIZE_MAX = 1_000;

    /** Refresh tokens may last up to one year. */
    // PCOV has no line coverage for a class constant initializer.
    // @pest-mutate-ignore: IncrementInteger,DecrementInteger
    public const int REFRESH_TOKEN_TTL_DAYS_MAX = 365;

    /** The opt-in absolute lifetime still has a finite ceiling. */
    // PCOV has no line coverage for a class constant initializer.
    // @pest-mutate-ignore: IncrementInteger,DecrementInteger
    public const int COMPANION_GRANT_AGE_DAYS_MAX = 3_650;

    /**
     * Auth codes match Passport / league’s PT10M default and must not live longer.
     */
    // PCOV has no line coverage for a class constant initializer.
    // @pest-mutate-ignore: IncrementInteger,DecrementInteger
    public const int AUTH_CODE_TTL_MINUTES_MAX = 10;

    /** Per-minute rate limiter ceilings (register / token). */
    // PCOV has no line coverage for a class constant initializer.
    // @pest-mutate-ignore: IncrementInteger,DecrementInteger
    public const int RATE_LIMIT_PER_MINUTE_MAX = 10_000;

    /** Hard ceiling for non-revoked Passport clients (DCR global cap). */
    // PCOV has no line coverage for a class constant initializer.
    // @pest-mutate-ignore: IncrementInteger,DecrementInteger
    public const int REGISTRATIONS_GLOBAL_CAP_MAX = 100_000;

    /** Ten years: retention beyond that is a legal hold, not a config value. */
    // PCOV has no line coverage for a class constant initializer.
    // @pest-mutate-ignore: IncrementInteger,DecrementInteger
    public const int REVOKED_RETENTION_DAYS_MAX = 3_650;

    /** One year: a registered client nobody uses is purged well before that. */
    // PCOV has no line coverage for a class constant initializer.
    // @pest-mutate-ignore: IncrementInteger,DecrementInteger
    public const int UNUSED_CLIENT_RETENTION_HOURS_MAX = 8_760;

    /** 1 MiB: a client metadata document is a few hundred bytes of JSON. */
    // PCOV has no line coverage for a class constant initializer.
    // @pest-mutate-ignore: IncrementInteger,DecrementInteger
    public const int CIMD_MAX_DOCUMENT_BYTES_MAX = 1_048_576;

    /** A metadata fetch runs inside the authorize request, so it stays short. */
    // PCOV has no line coverage for a class constant initializer.
    // @pest-mutate-ignore: IncrementInteger,DecrementInteger
    public const int CIMD_TIMEOUT_SECONDS_MAX = 30;

    /** One week: a cached metadata document must not outlive a client's key rotation for long. */
    // PCOV has no line coverage for a class constant initializer.
    // @pest-mutate-ignore: IncrementInteger,DecrementInteger
    public const int CIMD_CACHE_SECONDS_MAX = 604_800;

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
