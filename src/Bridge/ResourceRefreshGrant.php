<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Bridge;

use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Laravel\Passport\Passport;
use Laravel\Passport\Token;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Grant\RefreshTokenGrant;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;
use Psr\Http\Message\ServerRequestInterface;
use Qiick\McpOAuth\Contracts\GrantStore;
use Qiick\McpOAuth\Data\TokenResourceSelectionData;
use Qiick\McpOAuth\Internal\GrantBindingColumn;
use Qiick\McpOAuth\Services\ResourceIndicatorsService;

/**
 * RFC 8707 refresh across audiences consented in one grant. League validates
 * the original refresh, then receives the single scope approved for this
 * resource. Its existing compare-and-set rotation remains in force.
 *
 * @internal
 */
final class ResourceRefreshGrant extends RefreshTokenGrant
{
    public function __construct(
        RefreshTokenRepositoryInterface $refreshTokens,
        private readonly ConfigRepository $config,
        private readonly ResourceIndicatorsService $resourceIndicators,
    ) {
        parent::__construct($refreshTokens);
    }

    /** @return array<string, mixed> League's decrypted and validated refresh credential */
    protected function validateOldRefreshToken(ServerRequestInterface $request, string $clientId): array
    {
        $oldRefreshToken = parent::validateOldRefreshToken($request, $clientId);
        $currentRequest = request();
        $selection = TokenResourceSelectionData::from($currentRequest);

        if ($selection === null) {
            return $oldRefreshToken;
        }

        /** @var Token|null $accessToken */
        $accessToken = Passport::token()->newQuery()->find($oldRefreshToken['access_token_id']);
        $binding = $accessToken?->getAttribute(GrantBindingColumn::from($this->config));
        $userIdentifier = $oldRefreshToken['user_id'];
        $grant = is_string($binding) || is_int($binding) ? app(GrantStore::class)->find((string) $binding) : null;

        if ($grant === null || $grant->revoked || $grant->clientId !== $clientId
            || (! is_int($userIdentifier) && ! is_string($userIdentifier)) || $grant->userIdentifier !== (string) $userIdentifier) {
            throw OAuthServerException::invalidRefreshToken('Token has been revoked');
        }

        if ($this->resourceIndicators->scopeInGrant($grant, $selection->identifier) !== $selection->scope) {
            throw new OAuthServerException('The resource was not approved.', 0, 'invalid_target');
        }

        $currentRequest->attributes->set(TokenResourceSelectionData::REQUEST_ATTRIBUTE, new TokenResourceSelectionData(
            $selection->identifier, $selection->scope, $grant->id,
        ));
        $oldRefreshToken['scopes'] = [$selection->scope];

        return $oldRefreshToken;
    }
}
