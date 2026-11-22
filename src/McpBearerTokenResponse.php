<?php

declare(strict_types=1);

namespace Qiick\McpOAuth;

use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\ResponseTypes\BearerTokenResponse;

/**
 * Token endpoint JSON body for MCP OAuth. League’s stock Bearer response omits
 * `scope`; S21 / design §5.6 require the issued wire scopes in the body.
 *
 * @api
 */
final class McpBearerTokenResponse extends BearerTokenResponse
{
    /**
     * @return array{scope: string}
     */
    protected function getExtraParams(AccessTokenEntityInterface $accessToken): array
    {
        $scopeIdentifiers = array_map(
            static fn (ScopeEntityInterface $scope): string => $scope->getIdentifier(),
            $accessToken->getScopes(),
        );

        return [
            'scope' => implode(' ', $scopeIdentifiers),
        ];
    }
}
