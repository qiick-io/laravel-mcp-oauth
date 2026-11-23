<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Data;

use Qiick\McpOAuth\RedirectUriGuard;

/**
 * One admin-blocked redirect host as {@see RedirectUriGuard} applies it:
 * the host itself always, its subdomains unless the row's `match_mode` is
 * `exact`.
 *
 * @internal
 */
final readonly class BlockedRedirectHostData
{
    public function __construct(
        public string $host,
        public bool $shouldMatchSubdomains = true,
    ) {}
}
