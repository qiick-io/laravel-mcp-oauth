<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Data;

/**
 * Shipped metadata for a first-party Companion build. Its client identifier
 * is a CIMD URL and its callbacks are app-claimed HTTPS URIs.
 *
 * @api
 */
final readonly class CompanionClientDefinitionData
{
    /** @param list<string> $redirectUris */
    public function __construct(
        public string $identifier,
        public string $name,
        public array $redirectUris,
        public string $operatorName,
    ) {}
}
