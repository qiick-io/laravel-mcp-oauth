<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Events;

/**
 * Dispatched after `mcp-oauth:purge-revoked` deleted what was past the
 * 90-day retention (standards review M5). Counts and the cutoff only.
 *
 * @api
 */
final readonly class McpRevokedRecordsPurgedEvent
{
    public function __construct(
        public int $clientCount,
        public int $grantCount,
        public int $consentRecordCount,
        public string $cutoffIso8601,
    ) {}
}
