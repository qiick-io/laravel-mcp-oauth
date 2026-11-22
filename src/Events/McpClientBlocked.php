<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Events;

/**
 * Dispatched after commit when an admin blocks a client.
 *
 * @api
 */
final readonly class McpClientBlocked
{
    public function __construct(
        public string $clientId,
        public ?string $actorIdentifier,
    ) {}
}
