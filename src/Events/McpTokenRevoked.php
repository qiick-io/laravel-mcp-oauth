<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Events;

/**
 * Dispatched when a client revokes one of its tokens (RFC 7009). Ids only,
 * never token material. `grantId` is null for a token bound to no grant.
 *
 * @api
 */
final readonly class McpTokenRevoked
{
    /**
     * @param  'access_token'|'refresh_token'  $tokenType
     */
    public function __construct(
        public string $clientId,
        public string $userIdentifier,
        public ?string $grantId,
        public string $tokenType,
        public int $revokedTokenCount,
    ) {}
}
