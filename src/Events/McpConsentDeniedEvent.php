<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Events;

/**
 * Dispatched after commit when the user denies consent.
 *
 * @api
 */
final readonly class McpConsentDeniedEvent
{
    public function __construct(
        public string $clientId,
        public string $userIdentifier,
    ) {}
}
