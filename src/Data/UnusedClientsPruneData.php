<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Data;

use DateTimeImmutable;

/**
 * What one run of `mcp-oauth:prune-unused-clients` deleted, or would delete.
 */
final readonly class UnusedClientsPruneData
{
    public function __construct(
        public int $clientCount,
        public DateTimeImmutable $cutoff,
    ) {}
}
