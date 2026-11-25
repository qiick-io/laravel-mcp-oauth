<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Actions;

use Illuminate\Contracts\Auth\Authenticatable;
use Laravel\Passport\Passport;
use Qiick\McpOAuth\Contracts\GrantStore;
use Qiick\McpOAuth\Data\GrantRecord;
use Qiick\McpOAuth\Data\RevocationReason;
use Qiick\McpOAuth\Events\McpGrantRevoked;
use Qiick\McpOAuth\Internal\PassportUserIdentifier;

/**
 * A user revokes an app from Connected apps (design §5.2): the grant is
 * revoked with {@see RevocationReason::User}, then every token bound to it,
 * so the app's next `/mcp` call and refresh fail, and the user's unexchanged
 * auth codes for that client (S76), so a code already in flight cannot be
 * exchanged later. The client stays: the user may authorise it again.
 *
 * Dispatches {@see McpGrantRevoked}.
 */
final class RevokeConnectedAppAction
{
    public function __construct(
        private readonly GrantStore $grantStore,
        private readonly RevokeGrantTokensAction $revokeGrantTokens,
    ) {}

    public function execute(GrantRecord $grant, Authenticatable $user): void
    {
        $userIdentifier = PassportUserIdentifier::of($user);

        $this->grantStore->revoke($grant->id, $userIdentifier, RevocationReason::User);
        $this->revokeGrantTokens->execute($grant);
        Passport::authCode()->newQuery()
            ->where('client_id', $grant->clientId)
            ->where('user_id', $grant->userIdentifier)
            ->update(['revoked' => true]);

        event(new McpGrantRevoked($grant->id, $grant->clientId, $grant->userIdentifier, $userIdentifier, RevocationReason::User));
    }
}
