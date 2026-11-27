<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Events;

/**
 * Dispatched after commit when refresh reuse revokes the token family.
 *
 * @api
 */
final readonly class McpRefreshTokenReusedEvent
{
    public function __construct(
        public string $clientId,
        public string $userIdentifier,
        public string $grantId,
        public int $revokedTokenCount,
    ) {}
}
