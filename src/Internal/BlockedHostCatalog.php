<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Internal;

use Qiick\McpOAuth\RedirectUriGuard;

/**
 * Supplies normalised ASCII blocked hosts for {@see RedirectUriGuard}.
 * The Eloquent-backed catalog lands with the migrations PR; tests inject a fixed list.
 */
final class BlockedHostCatalog
{
    /**
     * @param  list<string>  $hosts
     */
    public function __construct(
        private readonly array $hosts = [],
    ) {}

    /**
     * @return list<string>
     */
    public function all(): array
    {
        return $this->hosts;
    }
}
