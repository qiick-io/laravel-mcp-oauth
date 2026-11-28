<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Events;

use Qiick\McpOAuth\Data\RevocationReason;

/**
 * Dispatched after commit when a grant is revoked.
 *
 * @api
 */
final readonly class McpGrantRevokedEvent
{
    public function __construct(
        public string $grantId,
        public string $clientId,
        public string $userIdentifier,
        public ?string $actorIdentifier,
        public RevocationReason $reason,
        public ?string $installId = null,
    ) {}
}
