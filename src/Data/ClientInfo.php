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
     * @param  bool  $isRedirectLoopbackOnly  every redirect URI is loopback http (S3)
     */
    public function __construct(
        public string $id,
        public string $name,
        public string $redirectHost,
        public array $redirectUris,
        public bool $isRedirectLoopbackOnly = false,
    ) {}
}
