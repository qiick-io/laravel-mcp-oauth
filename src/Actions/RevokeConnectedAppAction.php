<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Actions;

use Illuminate\Contracts\Auth\Authenticatable;
use Qiick\McpOAuth\Contracts\GrantStore;
use Qiick\McpOAuth\Data\GrantRecord;
use Qiick\McpOAuth\Data\RevocationReason;
use Qiick\McpOAuth\Events\McpGrantRevoked;
use Qiick\McpOAuth\Internal\PassportUserIdentifier;

/**
 * A user revokes an app from Connected apps (design §5.2): the grant is
 * revoked with {@see RevocationReason::User}, then every token bound to it,
 * so the app's next `/mcp` call and refresh fail. The client stays: the user
 * may authorise it again.
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

        event(new McpGrantRevoked($grant->id, $grant->clientId, $grant->userIdentifier, $userIdentifier, RevocationReason::User));
    }
}
