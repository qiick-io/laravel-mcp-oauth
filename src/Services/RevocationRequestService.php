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
 * client id comes from the body or the HTTP Basic username, never both; a
 * confidential client must also present its secret, in the body or as the
 * Basic password. Only a client the package registered (its
 * `oauth_client_metadata` row) can revoke: no other client holds MCP tokens.
 * A public client (every DCR client) is identified by its id alone, which is
 * enough: it can only revoke tokens that were issued to it.
 *
 * Refusals use the token endpoint's bodies: a missing or repeated parameter
 * is `invalid_request`, any client that does not authenticate is the same
 * 401 `invalid_client`.
 *
 * @internal
 */
final class RevocationRequestService
{
    public function __construct(
        private readonly Hasher $hasher,
        private readonly TokenErrorResponseService $tokenErrorResponses,
        private readonly ClientMetadataRegistryService $metadataClients,
    ) {}

    /**
     * @throws HttpResponseException with `invalid_request` or `invalid_client`
     */
    public function authenticatedClient(Request $request): Client
    {
        // RFC 7009 §2.1: application/x-www-form-urlencoded, never a JSON body.
        if ($request->isJson()) {
            throw new HttpResponseException($this->tokenErrorResponses->refusal('invalid_request'));
        }

        $bodyParameters = $request->request->all();
        $basicClientId = $request->getUser();
        $hasBodyCredentials = ($bodyParameters['client_id'] ?? null) !== null || ($bodyParameters['client_secret'] ?? null) !== null;

        // RFC 6749 §2.3: one authentication method per request, never Basic and the body together.
        if ($basicClientId !== null && $hasBodyCredentials) {
            throw new HttpResponseException($this->tokenErrorResponses->refusal('invalid_request'));
        }

        $clientId = $bodyParameters['client_id'] ?? $basicClientId;
        $clientSecret = $bodyParameters['client_secret'] ?? $request->getPassword();

        if (! is_string($clientId) || $clientId === '') {
            throw new HttpResponseException($this->tokenErrorResponses->refusal('invalid_request'));
        }

        // A non-UUID would make PostgreSQL throw on the uuid column.
        if (Str::isUuid($clientId)) {
            /** @var Client|null $client */
            $client = $this->metadataClients->isRegisteredWireUuid($clientId)
                ? Passport::client()->newQuery()->whereKey($clientId)->where('revoked', false)->first()
                : null;
        } else {
            $client = $basicClientId === null && $clientSecret === null ? $this->metadataClients->findForRevocation($clientId) : null;
        }

        if ($client === null
            || ! $this->presentsItsSecret($client, $clientSecret)) {
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

        // A public client is identified by its id alone; a secret it sends is
        // ignored, as Passport does at the token endpoint.
        if (! is_string($storedSecret) || $storedSecret === '') {
            return true;
        }

        // An empty secret never matches a hash, so it needs no case of its own.
        return is_string($clientSecret) && $this->hasher->check($clientSecret, $storedSecret);
    }
}
