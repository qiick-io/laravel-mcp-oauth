<?php

declare(strict_types=1);

namespace Qiick\McpOAuth;

use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Http\Request;
use Laravel\Passport\Client;
use Laravel\Passport\Passport;
use Laravel\Passport\Token;
use Lcobucci\JWT\Validation\RequiredConstraintsViolated;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\ResourceServer;
use Qiick\McpOAuth\Contracts\GrantAuthorizer;
use Qiick\McpOAuth\Contracts\GrantStore;
use Qiick\McpOAuth\Data\AuthorizationDecision;
use Qiick\McpOAuth\Data\GrantRecord;
use Qiick\McpOAuth\Internal\GrantBindingColumn;
use Qiick\McpOAuth\Models\OAuthClientMetadata;
use Symfony\Bridge\PsrHttpMessage\Factory\PsrHttpFactory;

/**
 * The use-time checks on an OAuth access token at `/mcp` (design §8.5), in
 * order, with nothing cached, so a revocation takes effect on the next call:
 *
 * 1. signature, expiry and token row (Passport's ResourceServer);
 * 2. the row exists and its audience is this MCP resource (RFC 8707);
 * 3. the client exists, is not revoked (a fresh query) and was registered by
 *    the package;
 * 4. none of the client's redirect hosts is blocked;
 * 5. the client and user have an active grant, and the token is bound to it;
 * 6. the wire scopes are exactly `mcp:use`;
 * 7. the product's GrantAuthorizer allows.
 *
 * A refusal is `invalid_token` with one of three descriptions (S60): expired,
 * revoked (the token, its client or its grant) or not valid; or the product's
 * own decision from step 7.
 *
 * @api
 */
final class AccessTokenAuthenticator
{
    private const string EXPIRED = 'The access token expired.';

    private const string REVOKED = 'The access token was revoked.';

    private const string NOT_VALID = 'The access token is not valid.';

    public function __construct(
        private readonly ResourceServer $resourceServer,
        private readonly McpOAuthServer $mcpOAuthServer,
        private readonly RedirectUriGuard $redirectUriGuard,
        private readonly GrantStore $grantStore,
        private readonly GrantAuthorizer $grantAuthorizer,
        private readonly ConfigRepository $config,
    ) {}

    /**
     * Checks the Bearer of `$request` itself, converted the way Passport's
     * TokenGuard converts it, never the container's current request: a
     * product calling this with a request of its own gets that request's
     * token checked.
     */
    public function authenticate(Request $request): GrantRecord|AuthorizationDecision
    {
        try {
            $validatedRequest = $this->resourceServer->validateAuthenticatedRequest(
                (new PsrHttpFactory)->createRequest($request),
            );
        } catch (OAuthServerException $exception) {
            return AuthorizationDecision::invalidToken(self::descriptionOf($exception));
        }

        // The row for this resource only (RFC 8707). Missing also when the row
        // was purged right after the check above.
        /** @var Token|null $accessToken */
        $accessToken = Passport::token()->newQuery()
            ->whereKey($validatedRequest->getAttribute('oauth_access_token_id'))
            ->where('audience', $this->mcpOAuthServer->resourceIdentifier())
            ->first();

        if ($accessToken === null) {
            return AuthorizationDecision::invalidToken(self::NOT_VALID);
        }

        /** @var Client|null $client */
        $client = Passport::client()->newQuery()
            ->whereKey($accessToken->getAttribute('client_id'))
            ->where('revoked', false)
            ->first();

        if ($client === null
            || ! OAuthClientMetadata::isRegisteredClient($client)
            || $this->redirectUriGuard->clientHasBlockedRedirectHost($client)) {
            return AuthorizationDecision::invalidToken(self::REVOKED);
        }

        /** @var array{client_id: string, user_id: int|string} $owner Passport writes both on every token */
        $owner = $accessToken->only(['client_id', 'user_id']);
        $grant = $this->grantStore->activeFor($owner['client_id'], (string) $owner['user_id']);

        if ($grant === null) {
            return AuthorizationDecision::invalidToken(self::REVOKED);
        }

        // The JWT `scopes` claim: league always writes a list, but a token
        // signed with the server key may carry none, or null.
        $scopes = $validatedRequest->getAttribute('oauth_scopes');

        if (! $this->isBoundTo($accessToken, $grant) || ! self::carriesOnlyTheWireScope($scopes)) {
            return AuthorizationDecision::invalidToken(self::NOT_VALID);
        }

        $decision = $this->grantAuthorizer->authorize($request, $grant);

        return $decision->isAllowed ? $grant : $decision;
    }

    /**
     * The database compares the binding, whatever type the product's key has.
     */
    private function isBoundTo(Token $accessToken, GrantRecord $grant): bool
    {
        return Passport::token()->newQuery()
            ->whereKey($accessToken->getKey())
            ->where(GrantBindingColumn::from($this->config), $this->grantStore->bindingKey($grant))
            ->exists();
    }

    /**
     * At least one scope, and every one exactly `mcp:use`. Compared strictly,
     * so a claim holding something other than strings is refused, not cast.
     */
    private static function carriesOnlyTheWireScope(mixed $scopes): bool
    {
        if (! is_array($scopes) || $scopes === []) {
            return false;
        }

        foreach ($scopes as $scope) {
            if ($scope !== McpOAuthServer::WIRE_SCOPE) {
                return false;
            }
        }

        return true;
    }

    /**
     * League's hints: a revoked or purged row is "has been revoked"; an
     * expired token fails the time constraint among the JWT checks.
     */
    private static function descriptionOf(OAuthServerException $exception): string
    {
        if ($exception->getHint() === 'Access token has been revoked') {
            return self::REVOKED;
        }

        $violations = $exception->getPrevious() instanceof RequiredConstraintsViolated
            ? $exception->getPrevious()->violations()
            : [];

        foreach ($violations as $violation) {
            if (str_contains($violation->getMessage(), 'expired')) {
                return self::EXPIRED;
            }
        }

        return self::NOT_VALID;
    }
}
