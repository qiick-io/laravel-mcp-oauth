<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Psr\Http\Message\ServerRequestInterface;
use Qiick\McpOAuth\Actions\RevokeTokenAction;
use Qiick\McpOAuth\Services\RevocationRequestService;

/**
 * `POST oauth/revoke` (RFC 7009): authenticates the client, revokes the token
 * if it is the client's, and answers 200 with an empty body whatever the
 * token was (§2.2), so the endpoint is not a token oracle.
 *
 * @internal
 */
final class RevokeTokenController
{
    public function __invoke(
        Request $request,
        ServerRequestInterface $psrRequest,
        RevocationRequestService $revocationRequests,
        RevokeTokenAction $revokeToken,
    ): Response {
        $client = $revocationRequests->authenticatedClient($request);

        $revokeToken->execute($client, $revocationRequests->token($request), $psrRequest);

        return new Response('', 200, ['Cache-Control' => 'no-store']);
    }
}
