<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Http\Controllers;

use Laravel\Passport\Http\Controllers\AccessTokenController;
use League\OAuth2\Server\AuthorizationServer;
use League\OAuth2\Server\Exception\OAuthServerException;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Qiick\McpOAuth\Actions\RevokeAuthCodeTokensAction;
use Qiick\McpOAuth\Services\TokenErrorResponseService;
use Symfony\Component\HttpFoundation\Response;

/**
 * `POST oauth/token`: Passport's token endpoint, behind
 * ValidateTokenRequestMiddleware. League runs the authorization code grant
 * (PKCE S256, since every code carries a challenge; one-shot codes through
 * OneShotAuthCodeRepository) and the refresh token
 * grant through FamilyRevokingRefreshTokenRepository; the provider has
 * already removed client_credentials. AccessTokenCreated binds each new
 * token to its grant.
 *
 * Two changes: TokenErrorResponseService renders every refusal, so the
 * endpoint never says which check failed (RFC 6749 §5.2); and a used code
 * replayed after it expired still revokes the tokens issued with it, because
 * league refuses it for its expiry before OneShotAuthCodeRepository sees it.
 *
 * @internal
 */
final class IssueTokenController extends AccessTokenController
{
    public function __construct(
        AuthorizationServer $server,
        private readonly TokenErrorResponseService $tokenErrorResponses,
        private readonly RevokeAuthCodeTokensAction $revokeAuthCodeTokens,
    ) {
        parent::__construct($server);
    }

    public function issueToken(ServerRequestInterface $psrRequest, ResponseInterface $psrResponse): Response
    {
        try {
            return $this->convertResponse($this->server->respondToAccessTokenRequest($psrRequest, $psrResponse));
        } catch (OAuthServerException $exception) {
            if ($exception->getHint() === 'Authorization code has expired') {
                /** @var array{code: string} $tokenRequest league has just decrypted this code */
                $tokenRequest = $psrRequest->getParsedBody();
                $this->revokeAuthCodeTokens->executeForExpiredCode($tokenRequest['code']);
            }

            return $this->tokenErrorResponses->fromException($exception);
        }
    }
}
