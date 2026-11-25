<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Exceptions;

use InvalidArgumentException;

/**
 * Boot-time config is invalid. Fail closed: never coerce or fall back.
 *
 * @api
 */
final class InvalidMcpOAuthConfigException extends InvalidArgumentException
{
    public static function invalidInteger(string $configKey, int $maximum): self
    {
        return new self(
            "mcp-oauth config [{$configKey}] must be an integer between 1 and {$maximum} (inclusive).",
        );
    }

    public static function outOfRange(string $configKey, int $configuredValue, int $maximum): self
    {
        return new self(
            "mcp-oauth config [{$configKey}] value {$configuredValue} is outside the allowed range 1..{$maximum}.",
        );
    }

    public static function cimdCacheBoundsReversed(int $cacheMinSeconds, int $cacheMaxSeconds): self
    {
        return new self(
            "mcp-oauth config [cimd.cache_min_seconds] {$cacheMinSeconds} must not exceed [cimd.cache_max_seconds] {$cacheMaxSeconds}.",
        );
    }

    public static function invalidSpecRevision(): self
    {
        return new self(
            'mcp-oauth config [spec_revision] must be an MCP spec revision date (YYYY-MM-DD).',
        );
    }

    public static function invalidGrantBindingColumn(): self
    {
        return new self(
            'mcp-oauth config [grant_binding_column] must name the oauth_access_tokens column that holds GrantStore::bindingKey().',
        );
    }

    /**
     * @param  class-string  $contract
     */
    public static function missingAdapter(string $contract, string $remedy): self
    {
        return new self(
            "mcp-oauth is enabled but [{$contract}] is not bound. {$remedy} Bind adapters in a service provider's register().",
        );
    }
}
