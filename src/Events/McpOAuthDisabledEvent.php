<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Events;

/**
 * Dispatched after commit when an admin switches OAuth off.
 *
 * @api
 */
final readonly class McpOAuthDisabledEvent
{
    public function __construct(
        public ?string $actorIdentifier,
    ) {}
}
