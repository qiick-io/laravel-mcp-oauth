<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Actions;

use Qiick\McpOAuth\Contracts\GrantStore;
use Qiick\McpOAuth\Models\OAuthAuthCodeExchange;

/**
 * Drops unconsumed code bindings when the code expires. An exchange remains
 * until its grant is revoked or gone, when a replay has no credentials left
 * to revoke. Refresh rotation may keep the grant active beyond the code's
 * original expiry.
 *
 * @internal
 */
final class PruneAuthCodeExchangesAction
{
    public function __construct(
        private readonly GrantStore $grantStore,
    ) {}

    /**
     * Walks the table by key (deleting behind the cursor is safe) and deletes
     * row by row: a daily job over at most one row per active grant and code.
     *
     * @return int the rows deleted, or that would be with $isDryRun
     */
    public function execute(bool $isDryRun): int
    {
        $prunedCount = 0;

        foreach (OAuthAuthCodeExchange::query()->lazyById(column: 'auth_code_id') as $exchange) {
            $shouldKeep = $exchange->expires_at !== null
                ? $exchange->expires_at->isFuture()
                : $this->grantStore->find($exchange->grant_id)?->revoked === false;

            if ($shouldKeep) {
                continue;
            }

            if (! $isDryRun) {
                $exchange->delete();
            }

            $prunedCount++;
        }

        return $prunedCount;
    }
}
