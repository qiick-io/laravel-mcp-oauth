<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Http\Controllers;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\StatefulGuard;
use Illuminate\Http\Exceptions\HttpResponseException;
use Illuminate\Http\Request;
use Laravel\Passport\Client;
use Laravel\Passport\ClientRepository;
use Laravel\Passport\Contracts\AuthorizationViewResponse;
use Laravel\Passport\Exceptions\OAuthServerException;
use Laravel\Passport\Http\Controllers\AuthorizationController;
use Laravel\Passport\Scope;
use League\OAuth2\Server\AuthorizationServer;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Qiick\McpOAuth\Services\AuthorizationResponseService;
use Symfony\Component\HttpFoundation\Response;

/**
 * `GET oauth/authorize`: Passport's authorization endpoint, behind
 * ValidateAuthorizationRequestMiddleware. Passport validates the request
 * with league, sends a guest to login (the full URL survives as intended)
 * and renders the consent page through ConsentPageService.
 *
 * Two changes (design §5.2 item 7, S43, M1):
 * - consent is asked every time: a grant narrows scopes, role and resources,
 *   and only the consent screen can ask for that again;
 * - an OAuth error league redirects to the client (`prompt=none` →
 *   `consent_required` / `login_required`) carries `iss` like every other
 *   authorization response.
 */
final class AuthorizeClientController extends AuthorizationController
{
    public function __construct(
        AuthorizationServer $server,
        StatefulGuard $guard,
        ClientRepository $clients,
        private readonly AuthorizationResponseService $authorizationResponses,
    ) {
        parent::__construct($server, $guard, $clients);
    }

    public function authorize(
        ServerRequestInterface $psrRequest,
        Request $request,
        ResponseInterface $psrResponse,
        AuthorizationViewResponse $viewResponse,
    ): Response|AuthorizationViewResponse {
        try {
            return parent::authorize($psrRequest, $request, $psrResponse, $viewResponse);
        } catch (OAuthServerException $exception) {
            throw new HttpResponseException(
                $this->authorizationResponses->forClient($request, $exception->getResponse()),
                $exception,
            );
        }
    }

    /**
     * @param  array<int, Scope>  $scopes
     */
    protected function hasGrantedScopes(Authenticatable $user, Client $client, array $scopes): bool
    {
        return false;
    }
}
