<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Actions;

use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Contracts\Events\Dispatcher;
use Laravel\Passport\Client;
use Laravel\Passport\Passport;
use Laravel\Passport\RefreshToken;
use Laravel\Passport\Token;
use League\OAuth2\Server\CryptTrait;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\ResourceServer;
use Psr\Http\Message\ServerRequestInterface;
use Qiick\McpOAuth\Bridge\FamilyRevokingRefreshTokenRepository;
use Qiick\McpOAuth\Contracts\AuditLogger;
use Qiick\McpOAuth\Contracts\GrantStore;
use Qiick\McpOAuth\Data\GrantRecord;
use Qiick\McpOAuth\Data\RevocationReason;
use Qiick\McpOAuth\Events\McpTokenRevoked;
use Qiick\McpOAuth\Internal\GrantBindingColumn;
use Qiick\McpOAuth\Models\OAuthConsentRecord;
use Throwable;

/**
 * A client revokes one of its tokens (RFC 7009 §2.1; standards review
 * Resolved #5, with the 2026-11-23 decision on access tokens):
 *
 * - **refresh token:** every access token of its family (same client, user
 *   and grant binding) is revoked, the family's refresh tokens are removed,
 *   and the grant is revoked with {@see RevocationReason::Client}, in one
 *   transaction on Passport's connection with its `oauth_grant_revoked`
 *   audit entry ({@see AuditLogger});
 * - **access token:** that token is revoked and the refresh tokens issued
 *   with it are removed (RFC 7009 allows it); the grant stays.
 *
 * Refresh tokens are removed rather than marked revoked: a revoked refresh
 * token presented later is read as reuse by FamilyRevokingRefreshTokenRepository
 * and would revoke the family again under RevocationReason::Reuse. A removed
 * one is simply unknown (S58), so the client's own revocation is never
 * mistaken for theft.
 *
 * A refresh token is judged as the token endpoint would judge it: expired or
 * unknown changes nothing (RFC 7009 §2.2); a rotated one, already revoked,
 * is reuse and revokes its family under RevocationReason::Reuse through
 * FamilyRevokingRefreshTokenRepository, so presenting a stolen token here
 * leaves the same theft signal as presenting it at `oauth/token`. Any other
 * token that is unknown, dead, forged or another client's changes nothing,
 * and the endpoint answers 200 either way. The `token_type_hint` is not
 * needed: a refresh token is the one that decrypts.
 */
final class RevokeTokenAction
{
    use CryptTrait;

    public function __construct(
        private readonly GrantStore $grantStore,
        private readonly FamilyRevokingRefreshTokenRepository $familyRevokingRefreshTokens,
        private readonly ResourceServer $resourceServer,
        private readonly ConfigRepository $config,
        private readonly Dispatcher $events,
        private readonly AuditLogger $auditLogger,
        string $tokenEncryptionKey,
    ) {
        $this->setEncryptionKey($tokenEncryptionKey);
    }

    public function execute(Client $client, string $token, ServerRequestInterface $psrRequest): void
    {
        $refreshTokenPayload = $this->refreshTokenPayloadOf($token);

        if ($refreshTokenPayload !== null) {
            $this->revokeRefreshToken($client, $refreshTokenPayload);

            return;
        }

        $this->revokeAccessToken($client, $token, $psrRequest);
    }

    /**
     * @param  array{client_id: string, refresh_token_id: string, access_token_id: string, expire_time: int}  $refreshTokenPayload
     */
    private function revokeRefreshToken(Client $client, array $refreshTokenPayload): void
    {
        // Another client's token, or one league would refuse as expired: nothing to do.
        if ($refreshTokenPayload['client_id'] !== $client->getKey() || $refreshTokenPayload['expire_time'] < time()) {
            return;
        }

        /** @var RefreshToken|null $refreshToken */
        $refreshToken = Passport::refreshToken()->newQuery()->find($refreshTokenPayload['refresh_token_id']);

        // Unknown, or already revoked through this endpoint (its row is deleted, S58).
        if ($refreshToken === null) {
            return;
        }

        // A rotated token coming back is reuse here too, as at the token endpoint:
        // the theft signal (RevocationReason::Reuse, McpRefreshTokenReused) is kept.
        if ($refreshToken->getAttribute('revoked') === true) {
            $this->familyRevokingRefreshTokens->revokeFamilyForRefreshToken($refreshTokenPayload['refresh_token_id']);

            return;
        }

        $accessToken = Passport::token()->newQuery()->find($refreshTokenPayload['access_token_id']);

        if (! $accessToken instanceof Token) {
            return;
        }

        // The family, the audit entry and the grant together or not at all,
        // holding the client's row lock so a concurrent revoke of the same
        // family runs after this one and finds its refresh token gone. The
        // grant is written last (AuditLogger): a failure before it leaves the
        // grant active, even in a GrantStore that commits on its own, so a
        // retry finds and records it. The event follows the commit.
        $grantBeingRevoked = null;

        try {
            /** @var array{grant: GrantRecord|null, revokedTokenCount: int}|null $revocation Laravel 12 types transaction() as mixed */
            $revocation = Passport::token()->getConnection()->transaction(function () use ($accessToken, $refreshTokenPayload, &$grantBeingRevoked): ?array {
                Passport::client()->newQuery()->whereKey($accessToken->getAttribute('client_id'))->lockForUpdate()->first();

                if (! Passport::refreshToken()->newQuery()->whereKey($refreshTokenPayload['refresh_token_id'])->exists()) {
                    return null;
                }

                $revokedTokenCount = $this->revokeFamilyTokens($accessToken);
                $grant = $this->boundGrantOf($accessToken);

                if ($grant !== null) {
                    $this->recordGrantRevokedByClient($grant);
                    $grantBeingRevoked = $grant;
                    $this->grantStore->revoke($grant->id, null, RevocationReason::Client);
                }

                return ['grant' => $grant, 'revokedTokenCount' => $revokedTokenCount];
            });
        } catch (Throwable $transactionFailure) {
            // A GrantStore on a connection of its own committed the revoke,
            // then Passport's transaction failed (its commit): the grant cannot
            // be un-revoked, so its family and its one entry are written again
            // and the revoke completes. Anything else is rethrown untouched.
            if ($grantBeingRevoked === null || $this->grantStore->activeFor($grantBeingRevoked->clientId, $grantBeingRevoked->userIdentifier)?->id === $grantBeingRevoked->id) {
                throw $transactionFailure;
            }

            app(ExceptionHandler::class)->report($transactionFailure);
            $revokedGrant = $grantBeingRevoked;
            /** @var array{grant: GrantRecord, revokedTokenCount: int} $revocation */
            $revocation = Passport::token()->getConnection()->transaction(function () use ($accessToken, $revokedGrant): array {
                $revokedTokenCount = $this->revokeFamilyTokens($accessToken);
                $this->recordGrantRevokedByClient($revokedGrant);

                return ['grant' => $revokedGrant, 'revokedTokenCount' => $revokedTokenCount];
            });
        }

        if ($revocation === null) {
            return;
        }

        $this->dispatchRevoked($accessToken, $revocation['grant'], 'refresh_token', $revocation['revokedTokenCount']);
    }

    /**
     * Revokes every access token of the family (same client, user and grant
     * binding) and removes its refresh tokens.
     *
     * @return int the tokens revoked or removed
     */
    private function revokeFamilyTokens(Token $accessToken): int
    {
        $bindingColumn = GrantBindingColumn::from($this->config);
        $familyAccessTokenIds = Passport::token()->newQuery()
            ->where('client_id', $accessToken->getAttribute('client_id'))
            ->where('user_id', $accessToken->getAttribute('user_id'))
            ->where($bindingColumn, $accessToken->getAttribute($bindingColumn))
            ->pluck('id')
            ->all();

        /** @var int $removedRefreshTokenCount */
        $removedRefreshTokenCount = Passport::refreshToken()->newQuery()->whereIn('access_token_id', $familyAccessTokenIds)->delete();

        return $removedRefreshTokenCount
            + Passport::token()->newQuery()->whereIn('id', $familyAccessTokenIds)->where('revoked', false)->update(['revoked' => true]);
    }

    private function recordGrantRevokedByClient(GrantRecord $grant): void
    {
        $this->auditLogger->record('oauth_grant_revoked', null, $grant->id, [
            'client_id' => $grant->clientId,
            'redirect_host' => OAuthConsentRecord::redirectHostOfGrant($grant->id),
            'reason' => RevocationReason::Client->value,
        ]);
    }

    private function revokeAccessToken(Client $client, string $token, ServerRequestInterface $psrRequest): void
    {
        try {
            // Signature, expiry and revocation, exactly as /mcp checks them. League
            // strips an optional `Bearer ` prefix, so the bare token is enough.
            $validatedRequest = $this->resourceServer->validateAuthenticatedRequest(
                $psrRequest->withHeader('Authorization', $token),
            );
        } catch (OAuthServerException) {
            return;
        }

        $accessToken = $validatedRequest->getAttribute('oauth_client_id') === $client->getKey()
            ? Passport::token()->newQuery()->find($validatedRequest->getAttribute('oauth_access_token_id'))
            : null;

        if (! $accessToken instanceof Token) {
            return;
        }

        /** @var int $removedRefreshTokenCount */
        $removedRefreshTokenCount = Passport::refreshToken()->newQuery()->where('access_token_id', $accessToken->getKey())->delete();
        $revokedTokenCount = $removedRefreshTokenCount
            + Passport::token()->newQuery()->whereKey($accessToken->getKey())->update(['revoked' => true]);

        $this->dispatchRevoked($accessToken, $this->boundGrantOf($accessToken), 'access_token', $revokedTokenCount);
    }

    /**
     * The client's active grant for this user, when the token is bound to it.
     */
    private function boundGrantOf(Token $accessToken): ?GrantRecord
    {
        ['client_id' => $clientId, 'user_id' => $userIdentifier] = self::ownerOf($accessToken);
        $grant = $this->grantStore->activeFor($clientId, $userIdentifier);

        // The database compares the binding, whatever type the product's key has.
        $isBoundToGrant = $grant !== null && Passport::token()->newQuery()
            ->whereKey($accessToken->getKey())
            ->where(GrantBindingColumn::from($this->config), $this->grantStore->bindingKey($grant))
            ->exists();

        return $isBoundToGrant ? $grant : null;
    }

    /**
     * @return array{client_id: string, user_id: string}
     */
    private static function ownerOf(Token $accessToken): array
    {
        /** @var array{client_id: string, user_id: int|string} $owner Passport writes both on every token */
        $owner = $accessToken->only(['client_id', 'user_id']);

        return ['client_id' => $owner['client_id'], 'user_id' => (string) $owner['user_id']];
    }

    /**
     * @param  'access_token'|'refresh_token'  $tokenType
     */
    private function dispatchRevoked(Token $accessToken, ?GrantRecord $grant, string $tokenType, int $revokedTokenCount): void
    {
        ['client_id' => $clientId, 'user_id' => $userIdentifier] = self::ownerOf($accessToken);

        $this->events->dispatch(new McpTokenRevoked(
            clientId: $clientId,
            userIdentifier: $userIdentifier,
            grantId: $grant?->id,
            tokenType: $tokenType,
            revokedTokenCount: $revokedTokenCount,
        ));
    }

    /**
     * League's refresh tokens are encrypted with Passport's key; anything
     * that does not decrypt is not one.
     *
     * @return array{client_id: string, refresh_token_id: string, access_token_id: string, expire_time: int}|null
     */
    private function refreshTokenPayloadOf(string $token): ?array
    {
        try {
            /** @var array{client_id: string, refresh_token_id: string, access_token_id: string, expire_time: int} $payload league's own refresh-token payload */
            $payload = json_decode($this->decrypt($token), true, flags: JSON_THROW_ON_ERROR);
        } catch (Throwable) {
            return null;
        }

        return $payload;
    }
}
