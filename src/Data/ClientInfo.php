<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Data;

/**
 * Passport client facts shown on consent and in admin lists.
 *
 * @api
 */
final readonly class ClientInfo
{
    /**
     * @param  list<string>  $redirectUris
     */
    public function __construct(
        public string $id,
        public string $name,
        public string $redirectHost,
        public array $redirectUris,
    ) {}
}
