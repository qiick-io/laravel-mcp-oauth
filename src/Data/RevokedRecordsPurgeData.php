<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Data;

use DateTimeImmutable;

/**
 * What one run of `mcp-oauth:purge-revoked` deleted, or would delete. The
 * grant count is null on a dry run: the product purges its own grants and
 * has no way to only count them.
 *
 * @internal
 */
final readonly class RevokedRecordsPurgeData
{
    public function __construct(
        public int $clientCount,
        public ?int $grantCount,
        public int $consentRecordCount,
        public DateTimeImmutable $cutoff,
    ) {}
}
