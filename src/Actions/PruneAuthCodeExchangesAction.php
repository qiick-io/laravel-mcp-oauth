<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Actions;

use Qiick\McpOAuth\Contracts\GrantStore;
use Qiick\McpOAuth\Models\OAuthAuthCodeExchange;

/**
 * Deletes the `oauth_auth_code_exchanges` rows whose grant is revoked or
 * gone. Such a grant's tokens are refused at use (design §8.5), so a code
 * presented again has nothing left to revoke. A row of an active grant stays
 * however old it is: refresh rotation keeps that grant's tokens alive past
 * any fixed window.
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
            if ($this->grantStore->find($exchange->grant_id)?->revoked === false) {
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
