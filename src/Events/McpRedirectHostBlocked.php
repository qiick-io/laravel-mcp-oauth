<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Events;

/**
 * Dispatched after commit when an admin blocks a redirect host.
 *
 * @api
 */
final readonly class McpRedirectHostBlocked
{
    public function __construct(
        public string $host,
        public ?string $actorIdentifier,
    ) {}
}
