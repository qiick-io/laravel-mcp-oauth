<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Events;

/**
 * Dispatched after commit when consent creates a new grant.
 *
 * @api
 */
final readonly class McpConsentApproved
{
    /**
     * @param  list<string>  $scopes
     * @param  list<string>  $resources
     */
    public function __construct(
        public string $clientId,
        public string $userIdentifier,
        public string $grantId,
        public string $redirectHost,
        public array $scopes,
        public array $resources,
        public ?string $resource = null,
    ) {}
}
