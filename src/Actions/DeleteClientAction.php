<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Actions;

use Laravel\Passport\Passport;
use Qiick\McpOAuth\Models\OAuthClientMetadata;

/**
 * Deletes a client the package registered with everything Passport keeps
 * for it: its codes, access tokens and their refresh tokens, and its
 * `oauth_client_metadata` row. Passport's tables have no foreign keys, so
 * nothing would cascade on its own.
 *
 * Not a full cascade: the client's consent records and auth-code exchanges
 * stay. They hold no credential, and their own retention removes them
 * (`retention_until` in mcp-oauth:purge-revoked, and
 * mcp-oauth:prune-auth-code-exchanges).
 *
 * @internal
 */
final class DeleteClientAction
{
    public function execute(string $clientId): void
    {
        // Ids read first: MySQL refuses an UPDATE or DELETE whose subquery reads the same table.
        $accessTokenIds = Passport::token()->newQuery()->where('client_id', $clientId)->pluck('id')->all();

        Passport::refreshToken()->newQuery()->whereIn('access_token_id', $accessTokenIds)->delete();
        Passport::token()->newQuery()->whereIn('id', $accessTokenIds)->delete();
        Passport::authCode()->newQuery()->where('client_id', $clientId)->delete();
        OAuthClientMetadata::query()->where('client_id', $clientId)->delete();
        Passport::client()->newQuery()->whereKey($clientId)->delete();
    }
}
