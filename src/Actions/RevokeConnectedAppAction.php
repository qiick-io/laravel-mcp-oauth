<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Actions;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Laravel\Passport\Passport;
use Qiick\McpOAuth\Contracts\GrantStore;
use Qiick\McpOAuth\Data\GrantRecord;
use Qiick\McpOAuth\Data\RevocationReason;
use Qiick\McpOAuth\Events\McpGrantRevoked;
use Qiick\McpOAuth\Internal\BoundedPositiveInt;
use Qiick\McpOAuth\Internal\PassportUserIdentifier;

/**
 * A user revokes an app from Connected apps (design §5.2): the grant is
 * revoked with {@see RevocationReason::User}, then every token bound to it,
 * so the app's next `/mcp` call and refresh fail, and the user's unexchanged
 * auth codes for that client that this grant issued (S76), so a code already
 * in flight cannot be exchanged later. The client stays: the user may
 * authorise it again.
 *
 * Codes carry no grant, so "this grant's codes" is read from time: only codes
 * issued before the revoke began (Passport writes `expires_at` as the issue
 * time plus the code TTL), and only while no newer grant is active for that
 * client and user. A newer consent already revoked the older codes when it
 * was approved, and its own code must survive (#49 review). A code issued in
 * the second the revoke began is kept: if it was the older grant's, its
 * exchange still fails (S54: a token for a revoked grant is revoked at once).
 *
 * Dispatches {@see McpGrantRevoked}.
 */
final class RevokeConnectedAppAction
{
    public function __construct(
        private readonly GrantStore $grantStore,
        private readonly RevokeGrantTokensAction $revokeGrantTokens,
        private readonly ConfigRepository $config,
    ) {}

    public function execute(GrantRecord $grant, Authenticatable $user): void
    {
        $userIdentifier = PassportUserIdentifier::of($user);
        $revokeStartedAt = now()->startOfSecond();

        $authCodeTtlMinutes = BoundedPositiveInt::require(
            $this->config->get('mcp-oauth.auth_code_ttl_minutes'),
            'auth_code_ttl_minutes',
            BoundedPositiveInt::AUTH_CODE_TTL_MINUTES_MAX,
        );

        // One transaction on Passport's connection: the tokens and codes are
        // revoked together or not at all, and with them the product's grant
        // when its GrantStore writes on that connection. The event follows
        // the commit, so listeners never hear of a revoke that rolled back.
        Passport::token()->getConnection()->transaction(function () use ($grant, $userIdentifier, $revokeStartedAt, $authCodeTtlMinutes): void {
            $this->grantStore->revoke($grant->id, $userIdentifier, RevocationReason::User);
            $this->revokeGrantTokens->execute($grant);

            if ($this->grantStore->activeFor($grant->clientId, $grant->userIdentifier) === null) {
                Passport::authCode()->newQuery()
                    ->where('client_id', $grant->clientId)
                    ->where('user_id', $grant->userIdentifier)
                    ->where('expires_at', '<', $revokeStartedAt->copy()->addMinutes($authCodeTtlMinutes))
                    ->update(['revoked' => true]);
            }
        });

        event(new McpGrantRevoked($grant->id, $grant->clientId, $grant->userIdentifier, $userIdentifier, RevocationReason::User));
    }
}
