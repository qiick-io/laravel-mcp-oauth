<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Events;

/**
 * Dispatched after commit when consent creates a new grant.
 *
 * @api
 */
final readonly class McpConsentApprovedEvent
{
    /**
     * @param  list<string>  $scopes
     * @param  list<string>  $resources
     * @param  array<string, string>  $resourceScopes  protocol audiences and their approved wire scopes
     */
    public function __construct(
        public string $clientId,
        public string $userIdentifier,
        public string $grantId,
        public string $redirectHost,
        public array $scopes,
        public array $resources,
        public ?string $resource = null,
        public array $resourceScopes = [],
    ) {}
}
