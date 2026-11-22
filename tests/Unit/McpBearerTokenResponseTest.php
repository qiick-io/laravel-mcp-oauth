<?php

declare(strict_types=1);

use Laravel\Passport\Bridge\AccessToken;
use Laravel\Passport\Bridge\Client;
use Laravel\Passport\Bridge\Scope;
use Laravel\Passport\Passport;
use Qiick\McpOAuth\McpBearerTokenResponse;
use Qiick\McpOAuth\McpOAuthServer;
use ReflectionMethod;

/**
 * S21 / design §5.6: token JSON must name the issued wire scope(s).
 */
it('adds a space-separated scope field from the access token scopes', function (): void {
    $accessToken = new AccessToken(
        'user-1',
        [new Scope(McpOAuthServer::WIRE_SCOPE), new Scope('extra:scope')],
        new Client('client-1', 'Test', redirectUri: [], isConfidential: false),
    );

    $method = new ReflectionMethod(McpBearerTokenResponse::class, 'getExtraParams');

    expect($method->invoke(new McpBearerTokenResponse, $accessToken))->toBe([
        'scope' => McpOAuthServer::WIRE_SCOPE.' extra:scope',
    ]);
});

it('emits an empty scope string when the access token has no scopes', function (): void {
    $accessToken = new AccessToken(
        'user-1',
        [],
        new Client('client-1', 'Test', redirectUri: [], isConfidential: false),
    );

    $method = new ReflectionMethod(McpBearerTokenResponse::class, 'getExtraParams');

    expect($method->invoke(new McpBearerTokenResponse, $accessToken))->toBe([
        'scope' => '',
    ]);
});

it('registers McpBearerTokenResponse as Passport authorization server response type', function (): void {
    expect(Passport::$authorizationServerResponseType)->toBeInstanceOf(McpBearerTokenResponse::class);
});
