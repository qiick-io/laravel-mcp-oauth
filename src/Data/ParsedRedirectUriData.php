<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Data;

/**
 * Result of the single canonical redirect-URI parse used by every guard check
 * (registration, scheme, hostOf, blocklist, exact equality). Keeps those paths
 * from diverging.
 *
 * @internal
 */
final readonly class ParsedRedirectUriData
{
    public function __construct(
        public string $scheme,
        public ?string $normalizedHost,
        public ?int $port = null,
        public string $path = '',
        public ?string $query = null,
    ) {}
}
