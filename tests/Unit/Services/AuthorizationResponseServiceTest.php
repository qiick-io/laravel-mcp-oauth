<?php

declare(strict_types=1);

use Illuminate\Http\JsonResponse;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use League\OAuth2\Server\AuthorizationServer;
use Qiick\McpOAuth\McpOAuthServer;
use Qiick\McpOAuth\Services\AuthorizationResponseService;

function authorizationResponseService(): AuthorizationResponseService
{
    return new AuthorizationResponseService(Mockery::mock(AuthorizationServer::class), app(McpOAuthServer::class));
}

it('returns a response that is not a redirect untouched', function (): void {
    $jsonError = new JsonResponse(['error' => 'invalid_request'], 400);

    $response = authorizationResponseService()->forClient(Request::create('/oauth/authorize'), $jsonError);

    expect($response)->toBe($jsonError)
        ->and($response->headers->has('Location'))->toBeFalse();
});

it('starts the query with iss when the client URI has none', function (): void {
    $response = authorizationResponseService()->forClient(
        Request::create('/oauth/authorize'),
        new RedirectResponse('cursor://callback'),
    );

    expect($response->headers->get('Location'))->toBe('cursor://callback?iss='.rawurlencode('https://mcp-oauth.test'));
});

it('answers an Inertia visit with an empty 409 and the client location', function (): void {
    $request = Request::create('/oauth/authorize', 'POST', server: ['HTTP_X_INERTIA' => 'true']);

    $response = authorizationResponseService()->forClient($request, new RedirectResponse('https://app.example/cb?code=x'));

    expect($response->getStatusCode())->toBe(409)
        ->and($response->getContent())->toBe('')
        ->and($response->headers->get('X-Inertia-Location'))->toBe('https://app.example/cb?code=x&iss='.rawurlencode('https://mcp-oauth.test'));
});
