<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Internal;

use Qiick\McpOAuth\Models\OAuthBlockedRedirectHost;
use Qiick\McpOAuth\RedirectUriGuard;

/**
 * Supplies normalised ASCII blocked hosts for {@see RedirectUriGuard}.
 * A fixed list is for unit tests; production loads non-expired rows from
 * {@see OAuthBlockedRedirectHost}.
 */
final class BlockedHostCatalog
{
    /**
     * @param  list<string>|null  $hosts  null loads from the database
     */
    public function __construct(
        private readonly ?array $hosts = null,
    ) {}

    /**
     * @return list<string>
     */
    public function all(): array
    {
        if ($this->hosts !== null) {
            return $this->hosts;
        }

        /** @var list<string> $hosts */
        $hosts = OAuthBlockedRedirectHost::query()
            ->where(static function ($hostQuery): void {
                $hostQuery->whereNull('expires_at')
                    ->orWhere('expires_at', '>', now());
            })
            ->pluck('host')
            ->all();

        return $hosts;
    }
}
