<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Bridge;

use Laravel\Passport\Bridge\ScopeRepository;
use Laravel\Passport\ClientRepository;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\Exception\OAuthServerException;
use Qiick\McpOAuth\Contracts\GrantStore;
use Qiick\McpOAuth\Data\TokenResourceSelectionData;
use Qiick\McpOAuth\McpOAuthServer;
use Qiick\McpOAuth\Models\OAuthAuthCodeExchange;
use Qiick\McpOAuth\Services\ResourceIndicatorsService;

/**
 * Limits the code exchange to one scope from the grant recorded when League
 * consumed the code. Passport still applies its own client scope policy.
 *
 * @internal
 */
final class ResourceScopeRepository extends ScopeRepository
{
    public function __construct(
        ClientRepository $clients,
        private readonly McpOAuthServer $server,
        private readonly ResourceIndicatorsService $resourceIndicators,
    ) {
        parent::__construct($clients);
    }

    /**
     * @param  list<ScopeEntityInterface>  $scopes
     * @return list<ScopeEntityInterface>
     *
     * @throws OAuthServerException when the user or the client did not approve the selected pair
     */
    public function finalizeScopes(
        array $scopes,
        string $grantType,
        ClientEntityInterface $clientEntity,
        ?string $userIdentifier = null,
        ?string $authCodeId = null,
    ): array {
        $finalizedScopes = array_values(parent::finalizeScopes($scopes, $grantType, $clientEntity, $userIdentifier, $authCodeId));
        $request = request();
        $selection = TokenResourceSelectionData::from($request);

        if ($selection === null) {
            return $finalizedScopes;
        }

        if ($grantType === 'authorization_code' && $authCodeId !== null) {
            $exchange = OAuthAuthCodeExchange::query()->find($authCodeId);
            $grant = $exchange === null ? null : app(GrantStore::class)->find($exchange->grant_id);

            if ($grant === null && $selection->identifier === $this->server->resourceIdentifier()
                && $finalizedScopes === $scopes && count($scopes) === 1) {
                // The legacy bridge issues an immediately revoked token if consent vanished during exchange.
                return $finalizedScopes;
            }

            if ($grant === null || $grant->revoked || $grant->clientId !== $clientEntity->getIdentifier()
                || $grant->userIdentifier !== $userIdentifier
                || $this->resourceIndicators->scopeInGrant($grant, $selection->identifier) !== $selection->scope) {
                throw new OAuthServerException('The resource was not approved.', 0, 'invalid_target');
            }

            $request->attributes->set(TokenResourceSelectionData::REQUEST_ATTRIBUTE, new TokenResourceSelectionData(
                $selection->identifier, $selection->scope, $grant->id,
            ));
        }

        foreach ($finalizedScopes as $scope) {
            if ($scope->getIdentifier() === $selection->scope) {
                return [$scope];
            }
        }

        throw OAuthServerException::invalidScope($selection->scope);
    }
}
