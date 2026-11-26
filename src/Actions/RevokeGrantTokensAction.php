<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Actions;

use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Laravel\Passport\Passport;
use Qiick\McpOAuth\Contracts\GrantStore;
use Qiick\McpOAuth\Data\GrantRecord;
use Qiick\McpOAuth\Internal\GrantBindingColumn;

/**
 * Revokes every access token bound to a grant (the binding column holds
 * GrantStore::bindingKey()) and the refresh tokens issued with them. The
 * grant itself is the caller's to revoke, first, so a token still being
 * bound finds it revoked (BindAccessTokenAction).
 *
 * @internal
 */
final class RevokeGrantTokensAction
{
    public function __construct(
        private readonly GrantStore $grantStore,
        private readonly ConfigRepository $config,
    ) {}

    public function execute(GrantRecord $grant): void
    {
        // Ids read first: MySQL refuses an UPDATE whose subquery reads the same table (error 1093).
        $grantAccessTokenIds = Passport::token()->newQuery()
            ->where('client_id', $grant->clientId)
            ->where(GrantBindingColumn::from($this->config), $this->grantStore->bindingKey($grant))
            ->pluck('id')
            ->all();

        Passport::refreshToken()->newQuery()->whereIn('access_token_id', $grantAccessTokenIds)->update(['revoked' => true]);
        Passport::token()->newQuery()->whereIn('id', $grantAccessTokenIds)->update(['revoked' => true]);
    }
}
