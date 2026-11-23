<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Actions;

use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Laravel\Passport\Passport;
use Qiick\McpOAuth\Contracts\GrantStore;
use Qiick\McpOAuth\Exceptions\InvalidMcpOAuthConfigException;
use Qiick\McpOAuth\McpOAuthServer;

/**
 * Binds a freshly issued access token to the grant it acts under and to its
 * audience (design §8.4). Runs synchronously on Passport's
 * AccessTokenCreated, for the code exchange and every refresh alike, so the
 * token is bound before the response reaches the client.
 *
 * The grant is {@see GrantStore::activeFor()} of the token's client and user;
 * its {@see GrantStore::bindingKey()} goes into the configured binding
 * column. The audience is this server's MCP resource identifier: the token
 * endpoint refuses any other `resource`, so every token it mints is for
 * `/mcp`, and `/mcp` refuses a token that names anything else.
 *
 * A token with no user or no active grant (revoked between consent and the
 * exchange, S54) is revoked at once: it could never authorize a call, and
 * FamilyRevokingRefreshTokenRepository refuses its refresh token (S59).
 */
final class BindAccessTokenAction
{
    public function __construct(
        private readonly GrantStore $grantStore,
        private readonly McpOAuthServer $mcpOAuthServer,
        private readonly ConfigRepository $config,
    ) {}

    public function execute(string $accessTokenId, ?string $userIdentifier, string $clientId): void
    {
        $grant = $userIdentifier === null ? null : $this->grantStore->activeFor($clientId, $userIdentifier);
        $accessTokenQuery = Passport::token()->newQuery()->whereKey($accessTokenId);

        if ($grant === null) {
            $accessTokenQuery->update(['revoked' => true]);

            return;
        }

        $accessTokenQuery->update([
            $this->bindingColumn() => $this->grantStore->bindingKey($grant),
            'audience' => $this->mcpOAuthServer->resourceIdentifier(),
        ]);
    }

    /**
     * @throws InvalidMcpOAuthConfigException when the column is not a non-empty string
     */
    private function bindingColumn(): string
    {
        $bindingColumn = $this->config->get('mcp-oauth.grant_binding_column');

        if (! is_string($bindingColumn) || $bindingColumn === '') {
            throw InvalidMcpOAuthConfigException::invalidGrantBindingColumn();
        }

        return $bindingColumn;
    }
}
