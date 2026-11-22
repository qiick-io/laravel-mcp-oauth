<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Data;

/**
 * Typed consent vocabulary offered to the user for one client.
 *
 * @api
 */
final readonly class ConsentOptions
{
    /**
     * @param  list<ConsentOption>  $scopes
     * @param  list<ConsentOption>  $roles
     * @param  list<ConsentOption>  $resources
     * @param  list<string>  $notices
     */
    public function __construct(
        public array $scopes,
        public array $roles,
        public array $resources,
        public bool $resourcesRequired,
        public bool $canGrant,
        public array $notices = [],
    ) {}
}
