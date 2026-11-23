<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Services;

use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Http\Exceptions\HttpResponseException;
use Illuminate\Http\Request;
use Illuminate\Support\Str;
use Laravel\Passport\Client;
use Laravel\Passport\Passport;

/**
 * Reads `POST oauth/revoke` (RFC 7009 §2.1): the `token`, and the client that
 * sends it, authenticated as at the token endpoint (RFC 6749 §2.3). The
 * client id comes from the body or the HTTP Basic username; a confidential
 * client must also present its secret, in the body or as the Basic password.
 * A public client (every DCR client) is identified by its id alone, which is
 * enough: it can only revoke tokens that were issued to it.
 *
 * Refusals use the token endpoint's bodies: a missing or repeated parameter
 * is `invalid_request`, any client that does not authenticate is the same
 * 401 `invalid_client`.
 */
final class RevocationRequestService
{
    public function __construct(
        private readonly Hasher $hasher,
        private readonly TokenErrorResponseService $tokenErrorResponses,
    ) {}

    /**
     * @throws HttpResponseException with `invalid_request` or `invalid_client`
     */
    public function authenticatedClient(Request $request): Client
    {
        $bodyParameters = $request->request->all();
        $clientId = $bodyParameters['client_id'] ?? $request->getUser();
        $clientSecret = $bodyParameters['client_secret'] ?? $request->getPassword();

        if (! is_string($clientId) || $clientId === '') {
            throw new HttpResponseException($this->tokenErrorResponses->refusal('invalid_request'));
        }

        // A non-UUID would make PostgreSQL throw on the uuid column.
        /** @var Client|null $client */
        $client = Str::isUuid($clientId)
            ? Passport::client()->newQuery()->whereKey($clientId)->where('revoked', false)->first()
            : null;

        if ($client === null || ! $this->presentsItsSecret($client, $clientSecret)) {
            throw new HttpResponseException($this->tokenErrorResponses->invalidClient($request));
        }

        return $client;
    }

    /**
     * @throws HttpResponseException with `invalid_request`
     */
    public function token(Request $request): string
    {
        $token = $request->request->all()['token'] ?? null;

        if (! is_string($token) || $token === '') {
            throw new HttpResponseException($this->tokenErrorResponses->refusal('invalid_request'));
        }

        return $token;
    }

    private function presentsItsSecret(Client $client, mixed $clientSecret): bool
    {
        $storedSecret = $client->getAttribute('secret');

        if (! is_string($storedSecret) || $storedSecret === '') {
            return true;
        }

        // An empty secret never matches a hash, so it needs no case of its own.
        return is_string($clientSecret) && $this->hasher->check($clientSecret, $storedSecret);
    }
}
