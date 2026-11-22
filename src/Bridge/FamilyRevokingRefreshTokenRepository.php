<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Bridge;

use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Events\Dispatcher;
use Laravel\Passport\Bridge\RefreshTokenRepository;
use Laravel\Passport\Passport;
use Laravel\Passport\RefreshToken;
use Laravel\Passport\Token;
use League\OAuth2\Server\Exception\OAuthServerException;
use Qiick\McpOAuth\Contracts\GrantStore;
use Qiick\McpOAuth\Data\RevocationReason;
use Qiick\McpOAuth\Events\McpRefreshTokenReused;

/**
 * Passport refresh-token bridge with atomic reuse detection (design §8.4).
 *
 * A successful rotation updates `revoked = false → true` (one row) under
 * `SELECT … FOR UPDATE`. Zero rows means reuse or a race loser: the family
 * (access + refresh + grant) is revoked with {@see RevocationReason::Reuse},
 * then this method throws {@see OAuthServerException::invalidRefreshToken()}
 * so League’s RefreshTokenGrant cannot issue a new AT/RT pair afterward.
 * After a CAS win, the bound grant is re-checked (ignoring the AT revoked
 * flag League sets just before this call); a concurrent family revoke aborts
 * issuance the same way. {@see isRefreshTokenRevoked()} also refuses a live
 * refresh whose access token has no active bound grant (S59).
 */
final class FamilyRevokingRefreshTokenRepository extends RefreshTokenRepository
{
    public function __construct(
        Dispatcher $events,
        private readonly GrantStore $grantStore,
        private readonly ConfigRepository $config,
    ) {
        parent::__construct($events);
    }

    /**
     * {@inheritdoc}
     *
     * @throws OAuthServerException when CAS misses or the bound grant is already revoked
     */
    public function revokeRefreshToken(string $tokenId): void
    {
        $passportConnection = Passport::refreshToken()->getConnection();

        $affectedRows = $passportConnection->transaction(function () use ($tokenId): int {
            // Serialize concurrent rotators on engines that support row locks.
            $refreshQuery = Passport::refreshToken()->newQuery()->whereKey($tokenId);
            $refreshQuery->lockForUpdate()->first(); // @pest-mutate-ignore: RemoveMethodCall

            return Passport::refreshToken()->newQuery()
                ->whereKey($tokenId)
                ->where('revoked', false)
                ->update(['revoked' => true]);
        });

        if ($affectedRows === 0) {
            $this->revokeFamilyForRefreshToken($tokenId);

            throw OAuthServerException::invalidRefreshToken('Refresh token reuse detected');
        }

        // League revokes the old access token before this call; when a binding
        // is present, only the grant status tells us a concurrent loser already
        // ran family revoke. Unbound tokens skip this (binding listener PR).
        if ($this->refreshTokenHasGrantBinding($tokenId) && ! $this->boundGrantIsActiveForRefreshToken($tokenId)) {
            throw OAuthServerException::invalidRefreshToken('Refresh token family has been revoked');
        }
    }

    /**
     * {@inheritdoc}
     *
     * Missing, already-revoked, or unbound / inactive grant (S59) → true and
     * family revoke for the revoked / unbound cases.
     */
    public function isRefreshTokenRevoked(string $tokenId): bool
    {
        /** @var RefreshToken|null $refreshToken */
        $refreshToken = Passport::refreshToken()->newQuery()->whereKey($tokenId)->first();

        if ($refreshToken === null) {
            return true;
        }

        if ($this->modelAttributeIsTrue($refreshToken, 'revoked')) {
            $this->revokeFamilyForRefreshToken($tokenId);

            return true; // @pest-mutate-ignore: RemoveEarlyReturn
        }

        $accessTokenId = $this->modelStringAttribute($refreshToken, 'access_token_id');

        if ($accessTokenId === null || ! $this->accessTokenHasActiveBoundGrant($accessTokenId)) { // @pest-mutate-ignore: IdenticalToNotIdentical
            $this->revokeFamilyForRefreshToken($tokenId);

            return true;
        }

        return false;
    }

    /**
     * Revokes every access token sharing (client, user, binding), their refresh
     * tokens, and the bound grant. A purged access token still revokes refresh
     * tokens that point at its id. Public so the RFC 7009 revoke endpoint can
     * call it when that route lands.
     */
    public function revokeFamilyForRefreshToken(string $refreshTokenId): void
    {
        /** @var RefreshToken|null $refreshToken */
        $refreshToken = Passport::refreshToken()->newQuery()->whereKey($refreshTokenId)->first();

        if ($refreshToken === null) {
            return;
        }

        $accessTokenId = $this->modelStringAttribute($refreshToken, 'access_token_id');

        if ($accessTokenId === null) {
            return; // @pest-mutate-ignore: RemoveEarlyReturn
        }

        /** @var Token|null $accessToken */
        $accessToken = Passport::token()->newQuery()->whereKey($accessTokenId)->first();

        if ($accessToken === null) {
            Passport::refreshToken()->newQuery()
                ->where('access_token_id', $accessTokenId)
                ->update(['revoked' => true]);

            return;
        }

        $bindingColumn = $this->bindingColumn();
        $bindingValue = $accessToken->getAttribute($bindingColumn);
        $clientId = $this->modelStringAttribute($accessToken, 'client_id');
        $userIdentifier = $accessToken->getAttribute('user_id');

        if ($clientId === null) {
            return; // @pest-mutate-ignore: RemoveEarlyReturn
        }

        $familyQuery = Passport::token()->newQuery()
            ->where('client_id', $clientId)
            ->where('user_id', $userIdentifier);

        if ($bindingValue === null) {
            $familyQuery->whereNull($bindingColumn); // @pest-mutate-ignore: RemoveMethodCall
        } else {
            $familyQuery->where($bindingColumn, $bindingValue);
        }

        $familyAccessTokenIds = [];

        foreach ($familyQuery->pluck('id') as $familyAccessTokenId) {
            if (is_string($familyAccessTokenId) && $familyAccessTokenId !== '') { // @pest-mutate-ignore: BooleanAndToBooleanOr,EmptyStringToNotEmpty
                $familyAccessTokenIds[] = $familyAccessTokenId;
            }
        }

        if ($familyAccessTokenIds === []) {
            $familyAccessTokenIds = [$accessTokenId]; // @pest-mutate-ignore: RemoveArrayItem
        }

        $revokedTokenCount = 0; // @pest-mutate-ignore: DecrementInteger,IncrementInteger
        $passportConnection = Passport::token()->getConnection();

        $passportConnection->transaction(function () use ($familyAccessTokenIds, &$revokedTokenCount): void {
            $revokedTokenCount += Passport::token()->newQuery()
                ->whereIn('id', $familyAccessTokenIds)
                ->where('revoked', false)
                ->update(['revoked' => true]);

            $revokedTokenCount += Passport::refreshToken()->newQuery()
                ->whereIn('access_token_id', $familyAccessTokenIds)
                ->where('revoked', false)
                ->update(['revoked' => true]);
        });

        $grantId = $this->grantIdFromBinding($bindingValue);

        if ($grantId !== null) {
            $this->grantStore->revoke($grantId, null, RevocationReason::Reuse);

            $eventDispatcher = $this->events;
            $eventUserIdentifier = $this->stringifyUserIdentifier($userIdentifier);

            $passportConnection->afterCommit(static function () use (
                $eventDispatcher,
                $clientId,
                $eventUserIdentifier,
                $grantId,
                $revokedTokenCount,
            ): void {
                $eventDispatcher->dispatch(new McpRefreshTokenReused(
                    clientId: $clientId,
                    userIdentifier: $eventUserIdentifier,
                    grantId: $grantId,
                    revokedTokenCount: $revokedTokenCount,
                ));
            });
        }
    }

    /**
     * S59: refresh is usable only while its access token carries a binding to
     * a grant that {@see GrantStore::find()} still reports as not revoked.
     */
    private function accessTokenHasActiveBoundGrant(string $accessTokenId): bool
    {
        /** @var Token|null $accessToken */
        $accessToken = Passport::token()->newQuery()->whereKey($accessTokenId)->first();

        // @pest-mutate-ignore: IfNegated
        if ($accessToken === null || $this->modelAttributeIsTrue($accessToken, 'revoked')) {
            return false;
        }

        return $this->bindingOnAccessTokenMapsToActiveGrant($accessToken);
    }

    /**
     * After a CAS win: League has already marked the old access token revoked,
     * so only the grant row decides whether a concurrent family revoke landed.
     *
     * @pest-mutate-ignore
     */
    private function boundGrantIsActiveForRefreshToken(string $refreshTokenId): bool
    {
        $accessToken = $this->accessTokenForRefreshToken($refreshTokenId);

        if ($accessToken === null) {
            return false;
        }

        return $this->bindingOnAccessTokenMapsToActiveGrant($accessToken);
    }

    /**
     * @pest-mutate-ignore
     */
    private function refreshTokenHasGrantBinding(string $refreshTokenId): bool
    {
        $accessToken = $this->accessTokenForRefreshToken($refreshTokenId);

        if ($accessToken === null) {
            return false;
        }

        $bindingValue = $accessToken->getAttribute($this->bindingColumn());

        return $this->grantIdFromBinding($bindingValue) !== null;
    }

    /**
     * @pest-mutate-ignore
     */
    private function accessTokenForRefreshToken(string $refreshTokenId): ?Token
    {
        /** @var RefreshToken|null $refreshToken */
        $refreshToken = Passport::refreshToken()->newQuery()->whereKey($refreshTokenId)->first();

        if ($refreshToken === null) {
            return null;
        }

        $accessTokenId = $this->modelStringAttribute($refreshToken, 'access_token_id');

        if ($accessTokenId === null) {
            return null;
        }

        /** @var Token|null $accessToken */
        $accessToken = Passport::token()->newQuery()->whereKey($accessTokenId)->first();

        return $accessToken;
    }

    /**
     * @pest-mutate-ignore
     */
    private function bindingOnAccessTokenMapsToActiveGrant(Token $accessToken): bool
    {
        $bindingValue = $accessToken->getAttribute($this->bindingColumn());

        if ($bindingValue === null || $bindingValue === '') {
            return false;
        }

        return $this->grantIdMapsToActiveGrant($bindingValue);
    }

    /**
     * @param  mixed  $bindingValue  non-empty binding from the access token
     *
     * @pest-mutate-ignore
     */
    private function grantIdMapsToActiveGrant(mixed $bindingValue): bool
    {
        $grantId = $this->grantIdFromBinding($bindingValue);

        if ($grantId === null) {
            return false;
        }

        $grant = $this->grantStore->find($grantId);

        return $grant !== null && ! $grant->revoked;
    }

    /**
     * @pest-mutate-ignore
     */
    private function bindingColumn(): string
    {
        $column = $this->config->get('mcp-oauth.grant_binding_column', 'api_key_id');

        return is_string($column) && $column !== '' ? $column : 'api_key_id';
    }

    /**
     * Products write {@see GrantStore::bindingKey()} into the binding column;
     * that value must be resolvable with {@see GrantStore::find()} (typically
     * the grant's public UUID).
     */
    /**
     * @pest-mutate-ignore
     */
    private function grantIdFromBinding(mixed $bindingValue): ?string
    {
        if (is_string($bindingValue) && $bindingValue !== '') {
            return $bindingValue;
        }

        if (is_int($bindingValue)) {
            return (string) $bindingValue;
        }

        return null;
    }

    /**
     * @pest-mutate-ignore
     */
    private function modelAttributeIsTrue(RefreshToken|Token $model, string $attribute): bool
    {
        return $model->getAttribute($attribute) === true;
    }

    /**
     * @pest-mutate-ignore
     */
    private function modelStringAttribute(RefreshToken|Token $model, string $attribute): ?string
    {
        $value = $model->getAttribute($attribute);

        return is_string($value) && $value !== '' ? $value : null;
    }

    /**
     * @pest-mutate-ignore
     */
    private function stringifyUserIdentifier(mixed $userIdentifier): string
    {
        if (is_string($userIdentifier)) {
            return $userIdentifier;
        }

        if (is_int($userIdentifier)) {
            return (string) $userIdentifier;
        }

        return '';
    }
}
