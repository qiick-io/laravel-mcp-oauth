<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Internal;

use Qiick\McpOAuth\Data\BlockedRedirectHostData;
use Qiick\McpOAuth\Models\OAuthBlockedRedirectHost;
use Qiick\McpOAuth\RedirectUriGuard;

/**
 * Supplies blocked hosts and their match mode for {@see RedirectUriGuard}.
 * A fixed list is for unit tests; production loads non-expired rows from
 * {@see OAuthBlockedRedirectHost}. Only `exact` narrows a block to the host
 * itself: any other `match_mode` value, a typo included, also blocks the
 * subdomains, so a bad row errs towards refusing.
 *
 * @internal
 */
final class BlockedHostCatalog
{
    /**
     * @param  list<string|BlockedRedirectHostData>|null  $hosts  null loads from the database; a bare string blocks the host and its subdomains
     */
    public function __construct(
        private readonly ?array $hosts = null,
    ) {}

    /**
     * @return list<BlockedRedirectHostData>
     */
    public function all(): array
    {
        if ($this->hosts !== null) {
            return array_map(
                static fn (string|BlockedRedirectHostData $blockedHost): BlockedRedirectHostData => is_string($blockedHost)
                    ? new BlockedRedirectHostData($blockedHost)
                    : $blockedHost,
                $this->hosts,
            );
        }

        $blockedHostRows = OAuthBlockedRedirectHost::query()
            ->where(static function ($hostQuery): void {
                $hostQuery->whereNull('expires_at')
                    ->orWhere('expires_at', '>', now());
            })
            ->get(['host', 'match_mode']);
        $blockedHosts = [];

        foreach ($blockedHostRows as $blockedHostRow) {
            $blockedHosts[] = new BlockedRedirectHostData(
                $blockedHostRow->host,
                $blockedHostRow->match_mode !== OAuthBlockedRedirectHost::MATCH_MODE_EXACT,
            );
        }

        return $blockedHosts;
    }
}
