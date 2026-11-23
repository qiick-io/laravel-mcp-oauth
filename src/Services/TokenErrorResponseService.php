<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Services;

use Illuminate\Http\JsonResponse;
use League\OAuth2\Server\Exception\OAuthServerException;

/**
 * The one error body of `POST oauth/token` (RFC 6749 §5.2): `error` and a
 * fixed `error_description` per error code, never league's `hint`.
 *
 * League's hints say which check failed ("Authorization code has expired",
 * "Failed to verify `code_verifier`", "Token has been revoked", …). The
 * token endpoint is public, so every refusal of the same kind looks the same
 * and the details stay in the logs and events.
 *
 * League also answers `invalid_request` for a code it cannot decrypt, a code
 * of another client and a redirect URI that does not match. RFC 6749 §5.2
 * names those `invalid_grant`, so they are reclassified by their hint: the
 * hints are league's fixed strings, and the tests pin each case.
 */
final class TokenErrorResponseService
{
    public function fromException(OAuthServerException $exception): JsonResponse
    {
        $error = $exception->getErrorType();

        if ($error === 'invalid_request' && self::isInvalidGrantHint($exception->getHint())) {
            $error = 'invalid_grant';
        }

        // Keeps WWW-Authenticate for a client that authenticated with HTTP Basic (§5.2).
        return $this->response($error, $exception->getHttpStatusCode(), $exception->getHttpHeaders());
    }

    /**
     * @param  array<string, string>  $headers
     */
    public function refusal(string $error, int $status = 400, array $headers = []): JsonResponse
    {
        return $this->response($error, $status, $headers);
    }

    /**
     * @param  array<string, string>  $headers
     */
    private function response(string $error, int $status, array $headers): JsonResponse
    {
        $headers['Cache-Control'] = 'no-store';

        return new JsonResponse(['error' => $error, 'error_description' => self::descriptionOf($error)], $status, $headers);
    }

    private static function descriptionOf(string $error): string
    {
        return match ($error) {
            'invalid_request' => 'The request is missing a required parameter, repeats a parameter or is otherwise malformed.',
            'invalid_client' => 'Client authentication failed.',
            'invalid_grant' => 'The authorization code or refresh token is invalid, expired or revoked, does not match the redirect URI, or was issued to another client.',
            'unauthorized_client' => 'The client may not use this grant type.',
            'unsupported_grant_type' => 'Only the authorization_code and refresh_token grants are supported.',
            'invalid_scope' => 'The requested scope is invalid.',
            'invalid_target' => 'The resource parameter is required and must name this MCP endpoint.',
            default => 'The authorization server could not complete the request.',
        };
    }

    /**
     * League's hints of the `invalid_request` refusals that RFC 6749 §5.2
     * calls `invalid_grant`.
     */
    private static function isInvalidGrantHint(?string $hint): bool
    {
        return in_array($hint, [
            'Issue decrypting the authorization code',
            'Authorization code malformed',
            'Authorization code was not issued to this client',
            'Invalid redirect URI',
        ], true);
    }
}
