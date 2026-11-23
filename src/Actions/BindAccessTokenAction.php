<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Actions;

use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Laravel\Passport\Client;
use Laravel\Passport\Passport;
use Qiick\McpOAuth\Contracts\GrantStore;
use Qiick\McpOAuth\Data\GrantRecord;
use Qiick\McpOAuth\Internal\ConsumedAuthCodeGrant;
use Qiick\McpOAuth\Internal\GrantBindingColumn;
use Qiick\McpOAuth\McpOAuthServer;

/**
 * Binds a freshly issued access token to the grant it acts under and to its
 * audience (design §8.4). Runs synchronously on Passport's
 * AccessTokenCreated, for the code exchange and every refresh alike, so the
 * token is bound before the response reaches the client.
 *
 * Only tokens of MCP clients (allowed the `authorization_code` grant, as
 * every DCR client is) are bound; the product's own personal access tokens
 * are left alone. The grant is the one the code was consumed under for a
 * code exchange ({@see ConsumedAuthCodeGrant}), else
 * {@see GrantStore::activeFor()} of the token's client and user; its
 * {@see GrantStore::bindingKey()} goes into the configured binding
 * column. The audience is this server's MCP resource identifier: the token
 * endpoint refuses any other `resource`, so every token it mints is for
 * `/mcp`, and `/mcp` refuses a token that names anything else.
 *
 * A token with no user or no active grant (revoked between consent and the
 * exchange, S54, or by a concurrent replay of its code) is revoked at once: it could never authorize a call, and
 * FamilyRevokingRefreshTokenRepository refuses its refresh token (S59).
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
        /** @var Client|null $client */
        $client = Passport::client()->newQuery()->find($clientId);

        // Not an MCP client (a personal access or client credentials client of the product).
        if ($client === null || ! $client->hasGrantType('authorization_code')) {
            return;
        }

        $grant = $this->grantFor($clientId, $userIdentifier);
        $accessTokenQuery = Passport::token()->newQuery()->whereKey($accessTokenId);

        if ($grant === null || $grant->revoked) {
            $accessTokenQuery->update(['revoked' => true]);

            return;
        }

        $accessTokenQuery->update([
            GrantBindingColumn::from($this->config) => $this->grantStore->bindingKey($grant),
            'audience' => $this->mcpOAuthServer->resourceIdentifier(),
        ]);
    }

    /**
     * A code exchange binds to the grant its code was consumed under; a
     * refresh binds to the active grant, which S59 already requires.
     */
    private function grantFor(string $clientId, ?string $userIdentifier): ?GrantRecord
    {
        $consumedGrantId = $this->consumedAuthCodeGrant->take();

        if ($consumedGrantId !== null) {
            return $this->grantStore->find($consumedGrantId);
        }

        return $userIdentifier === null ? null : $this->grantStore->activeFor($clientId, $userIdentifier);
    }
}
