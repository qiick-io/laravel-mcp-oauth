<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Events;

/**
 * Dispatched after commit when unused clients are pruned.
 *
 * @api
 */
final readonly class McpUnusedClientsPrunedEvent
{
    public function __construct(
        public int $count,
        public string $cutoffIso8601,
    ) {}
}
