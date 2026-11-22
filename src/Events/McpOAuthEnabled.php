<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Events;

/**
 * Dispatched after commit when an admin switches OAuth on.
 *
 * @api
 */
final readonly class McpOAuthEnabled
{
    public function __construct(
        public ?string $actorIdentifier,
    ) {}
}
