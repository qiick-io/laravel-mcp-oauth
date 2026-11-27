<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Data;

use Qiick\McpOAuth\ClientMetadataUriGuard;

/**
 * Result of the single canonical redirect-URI parse used by every guard check
 * (registration, scheme, hostOf, blocklist, exact equality) and by
 * {@see ClientMetadataUriGuard}. Keeps those paths from
 * diverging. `isIpv6Literal` records a bracketed host even when the canonical
 * host is the IPv4 address it embeds (`[::ffff:a.b.c.d]` → `a.b.c.d`).
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
        public bool $isIpv6Literal = false,
    ) {}
}
