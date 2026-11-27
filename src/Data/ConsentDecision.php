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
     * @param  string|null  $resource  the MCP resource the grant is for (RFC 8707)
     * @param  string|null  $consentVersion  the version of the consent text the product showed
     * @param  string|null  $locale  the locale the page was shown in
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
        public ?string $resource = null,
        public ?string $consentVersion = null,
        public ?string $locale = null,
    ) {}
}
