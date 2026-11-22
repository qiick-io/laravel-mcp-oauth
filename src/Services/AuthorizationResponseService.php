<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Services;

use Illuminate\Http\Request;
use Illuminate\Http\Response as IlluminateResponse;
use Laravel\Passport\Http\Controllers\ConvertsPsrResponses;
use League\OAuth2\Server\AuthorizationServer;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\RequestTypes\AuthorizationRequestInterface;
use Psr\Http\Message\ResponseInterface;
use Qiick\McpOAuth\McpOAuthServer;
use Symfony\Component\HttpFoundation\Response;

/**
 * Turns a decided authorization request into the redirect back to the client
 * (design §8.3 steps 4–5):
 *
 * - approved: league issues the code; denied: league's `access_denied`;
 * - every redirect to the client carries `iss` = the issuer (RFC 9207 §2,
 *   standards review M1), error redirects included;
 * - an Inertia visit gets a 409 `X-Inertia-Location` so the browser leaves
 *   for the client's origin with a full page load (S51), without the package
 *   depending on Inertia.
 */
final class AuthorizationResponseService
{
    use ConvertsPsrResponses;

    public function __construct(
        private readonly AuthorizationServer $authorizationServer,
        private readonly McpOAuthServer $mcpOAuthServer,
    ) {}

    /**
     * Side effect: an approved request persists a new auth code (league).
     */
    public function complete(Request $request, AuthorizationRequestInterface $authorizationRequest): Response
    {
        /** @var ResponseInterface $psrResponse */
        $psrResponse = app(ResponseInterface::class);

        try {
            $clientRedirect = $this->convertResponse(
                $this->authorizationServer->completeAuthorizationRequest($authorizationRequest, $psrResponse),
            );
        } catch (OAuthServerException $exception) {
            $clientRedirect = $this->convertResponse($exception->generateHttpResponse($psrResponse));
        }

        return $this->forClient($request, $clientRedirect);
    }

    /**
     * Adds `iss` to a redirect to the client and adapts it to Inertia; any
     * other response is returned as is.
     */
    public function forClient(Request $request, Response $response): Response
    {
        $location = $response->headers->get('Location');

        // Only redirects to the client carry a Location here.
        if ($location === null) {
            return $response;
        }

        $location .= (str_contains($location, '?') ? '&' : '?').http_build_query(['iss' => $this->mcpOAuthServer->issuer()]);
        $response->headers->set('Location', $location);

        if ($request->header('X-Inertia') === null) {
            return $response;
        }

        return new IlluminateResponse('', 409, ['X-Inertia-Location' => $location]);
    }
}
