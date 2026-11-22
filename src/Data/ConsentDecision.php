<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Data;

/**
 * What the user approved. Product scopes only — never the wire scope mcp:use.
 *
 * @api
 */
final readonly class ConsentDecision
{
    /**
     * @param  list<string>  $scopes
     * @param  list<string>  $resources
     * @param  array<string, scalar|null>  $attributes
     */
    public function __construct(
        public string $clientId,
        public string $userIdentifier,
        public string $redirectUri,
        public array $scopes,
        public ?string $role,
        public array $resources,
        public bool $allResources,
        public array $attributes = [],
    ) {}
}
