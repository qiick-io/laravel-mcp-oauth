<?php

declare(strict_types=1);

use GuzzleHttp\Psr7\ServerRequest;
use League\OAuth2\Server\Exception\OAuthServerException;
use Qiick\McpOAuth\Services\TokenErrorResponseService;

/**
 * Every token-endpoint refusal: one fixed body per error code, never a hint,
 * and RFC 6749 §5.2 names for league's code and redirect mismatches.
 */
dataset('league_token_refusals', [
    'missing parameter' => [OAuthServerException::invalidRequest('code'), 400, 'invalid_request', 'The request is missing a required parameter, repeats a parameter or is otherwise malformed.'],
    'unknown client' => [OAuthServerException::invalidClient(new ServerRequest('POST', '/oauth/token')), 401, 'invalid_client', 'Client authentication failed.'],
    'expired code' => [OAuthServerException::invalidGrant('Authorization code has expired'), 400, 'invalid_grant', 'The authorization code or refresh token is invalid, expired or revoked, does not match the redirect URI, or was issued to another client.'],
    'revoked refresh token' => [OAuthServerException::invalidRefreshToken('Token has been revoked'), 400, 'invalid_grant', 'The authorization code or refresh token is invalid, expired or revoked, does not match the redirect URI, or was issued to another client.'],
    'grant not allowed for the client' => [OAuthServerException::unauthorizedClient(), 400, 'unauthorized_client', 'The client may not use this grant type.'],
    'unsupported grant' => [OAuthServerException::unsupportedGrantType(), 400, 'unsupported_grant_type', 'Only the authorization_code and refresh_token grants are supported.'],
    'unknown scope' => [OAuthServerException::invalidScope('admin'), 400, 'invalid_scope', 'The requested scope is invalid.'],
    'server error' => [OAuthServerException::serverError('Could not generate a random string'), 500, 'server_error', 'The authorization server could not complete the request.'],
]);

it('renders a league refusal as its fixed body without the hint', function (OAuthServerException $exception, int $status, string $error, string $description): void {
    $response = (new TokenErrorResponseService)->fromException($exception);

    expect($response->getStatusCode())->toBe($status)
        ->and($response->getData(true))->toBe(['error' => $error, 'error_description' => $description])
        ->and($response->headers->get('Content-Type'))->toBe('application/json')
        ->and($response->headers->get('Cache-Control'))->toContain('no-store');
})->with('league_token_refusals');

it('names league code and redirect mismatches invalid_grant', function (string $hint): void {
    $response = (new TokenErrorResponseService)->fromException(OAuthServerException::invalidRequest('code', $hint));

    expect($response->getStatusCode())->toBe(400)
        ->and($response->getData(true)['error'])->toBe('invalid_grant');
})->with([
    'Issue decrypting the authorization code',
    'Authorization code malformed',
    'Authorization code was not issued to this client',
    'Invalid redirect URI',
]);

it('keeps other invalid_request refusals as they are', function (?string $hint): void {
    $response = (new TokenErrorResponseService)->fromException(OAuthServerException::invalidRequest('code_verifier', $hint));

    expect($response->getData(true)['error'])->toBe('invalid_request');
})->with(['default hint' => [null], 'other hint' => ['Code Verifier must follow the specifications of RFC-7636.']]);

it('only reclassifies invalid_request, never another error with the same hint', function (): void {
    $exception = new OAuthServerException('Some message.', 3, 'invalid_scope', 400, 'Invalid redirect URI');

    expect((new TokenErrorResponseService)->fromException($exception)->getData(true)['error'])->toBe('invalid_scope');
});

it('challenges a client that authenticated with HTTP Basic', function (): void {
    $psrRequest = (new ServerRequest('POST', '/oauth/token'))->withHeader('Authorization', 'Basic '.base64_encode('client:'));

    $response = (new TokenErrorResponseService)->fromException(OAuthServerException::invalidClient($psrRequest));

    expect($response->getStatusCode())->toBe(401)
        ->and($response->headers->get('WWW-Authenticate'))->toBe('Basic realm="OAuth"');
});

it('renders a package refusal with the same body, status and headers', function (): void {
    $service = new TokenErrorResponseService;

    $targetRefusal = $service->refusal('invalid_target');
    $clientRefusal = $service->refusal('invalid_client', 401, ['WWW-Authenticate' => 'Basic realm="OAuth"']);

    expect($targetRefusal->getStatusCode())->toBe(400)
        ->and($targetRefusal->getData(true))->toBe([
            'error' => 'invalid_target',
            'error_description' => 'The resource parameter is required and must name this MCP endpoint.',
        ])
        ->and($targetRefusal->headers->get('Cache-Control'))->toContain('no-store')
        ->and($clientRefusal->getStatusCode())->toBe(401)
        ->and($clientRefusal->headers->get('WWW-Authenticate'))->toBe('Basic realm="OAuth"')
        ->and($clientRefusal->getData(true)['error_description'])->toBe('Client authentication failed.');
});
