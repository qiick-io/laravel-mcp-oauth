<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Http\Controllers;

use Laravel\Passport\Http\Controllers\AccessTokenController;
use League\OAuth2\Server\AuthorizationServer;
use League\OAuth2\Server\Exception\OAuthServerException;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Qiick\McpOAuth\Services\TokenErrorResponseService;
use Symfony\Component\HttpFoundation\Response;

/**
 * `POST oauth/token`: Passport's token endpoint, behind
 * ValidateTokenRequestMiddleware. League runs the authorization code grant
 * (PKCE S256, since every code carries a challenge) and the refresh token
 * grant through FamilyRevokingRefreshTokenRepository; the provider has
 * already removed client_credentials. AccessTokenCreated binds each new
 * token to its grant.
 *
 * The one change is the error body: TokenErrorResponseService renders every
 * refusal, so the endpoint never says which check failed (RFC 6749 §5.2).
 */
final class IssueTokenController extends AccessTokenController
{
    public function __construct(
        AuthorizationServer $server,
        private readonly TokenErrorResponseService $tokenErrorResponses,
    ) {
        parent::__construct($server);
    }

    public function issueToken(ServerRequestInterface $psrRequest, ResponseInterface $psrResponse): Response
    {
        try {
            return $this->convertResponse($this->server->respondToAccessTokenRequest($psrRequest, $psrResponse));
        } catch (OAuthServerException $exception) {
            return $this->tokenErrorResponses->fromException($exception);
        }
    }
}
