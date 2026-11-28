<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Actions;

use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Laravel\Passport\Passport;
use Qiick\McpOAuth\Contracts\GrantStore;
use Qiick\McpOAuth\Data\GrantRecord;
use Qiick\McpOAuth\Data\TokenResourceSelectionData;
use Qiick\McpOAuth\Internal\ConsumedAuthCodeGrant;
use Qiick\McpOAuth\Internal\GrantBindingColumn;
use Qiick\McpOAuth\McpOAuthServer;
use Qiick\McpOAuth\Models\OAuthClientMetadata;

/**
 * Binds a freshly issued access token to the grant it acts under and to its
 * audience (design §8.4). Runs synchronously on Passport's
 * AccessTokenCreated, for the code exchange and every refresh alike, so the
 * token is bound before the response reaches the client.
 *
 * Only tokens of MCP clients (those with an `oauth_client_metadata` row, which
 * DCR writes) are bound; the product's own Passport clients, personal access
 * or not, are left alone. The grant is the one the code was consumed under for a
 * code exchange ({@see ConsumedAuthCodeGrant}), else
 * {@see GrantStore::activeFor()} of the token's client and user; its
 * {@see GrantStore::bindingKey()} goes into the configured binding
 * column. The audience is the validated RFC 8707 resource selected at the
 * token endpoint, or the MCP identifier for the MCP-only flow.
 *
 * A token with no user or no active grant (revoked between consent and the
 * exchange, S54, or by a concurrent replay of its code) is revoked at once:
 * it could never authorize a call, and FamilyRevokingRefreshTokenRepository
 * refuses its refresh token (S59). The grant sits behind the product's
 * GrantStore, so no lock can be held on it; the order (bind, then read the
 * grant again) is what closes the race with a replay, because the replay
 * revokes the grant before it selects the grant's tokens.
 *
 * @internal
 */
final class BindAccessTokenAction
{
    public function __construct(
        private readonly GrantStore $grantStore,
        private readonly McpOAuthServer $mcpOAuthServer,
        private readonly ConfigRepository $config,
        private readonly ConsumedAuthCodeGrant $consumedAuthCodeGrant,
    ) {}

    public function execute(string $accessTokenId, ?string $userIdentifier, string $clientId): void
    {
        // Second guard: the endpoints already refuse clients the package did not register.
        if (! OAuthClientMetadata::isRegisteredClient($clientId)) {
            return;
        }

        $selection = TokenResourceSelectionData::from(request());
        $grant = $this->grantFor($clientId, $userIdentifier, $selection?->grantId);
        $accessTokenQuery = Passport::token()->newQuery()->whereKey($accessTokenId);

        if ($grant === null || $grant->revoked) {
            $accessTokenQuery->update(['revoked' => true]);

            return;
        }

        $accessTokenQuery->update([
            GrantBindingColumn::from($this->config) => $this->grantStore->bindingKey($grant),
            'audience' => $selection->identifier ?? $this->mcpOAuthServer->resourceIdentifier(),
        ]);

        // Bound first, then the grant read again: a concurrent replay of the
        // code either selects this token by its binding, or has already
        // revoked the grant, which this read then sees.
        if ($this->grantStore->find($grant->id)?->revoked !== false) {
            $accessTokenQuery->update(['revoked' => true]);
        }
    }

    /**
     * A code exchange binds to the grant its code was consumed under (none if
     * no grant was active then); a refresh binds to the active grant, which
     * S59 already requires.
     */
    private function grantFor(string $clientId, ?string $userIdentifier, ?string $selectedGrantId): ?GrantRecord
    {
        if ($this->consumedAuthCodeGrant->isRecorded()) {
            $consumedGrantId = $this->consumedAuthCodeGrant->take();

            // Consumed with no active grant: nothing may be bound, not even a later consent.
            return $consumedGrantId === null ? null : $this->grantStore->find($consumedGrantId);
        }

        if ($selectedGrantId !== null) {
            return $this->grantStore->find($selectedGrantId);
        }

        return $userIdentifier === null ? null : $this->grantStore->activeFor($clientId, $userIdentifier);
    }
}
