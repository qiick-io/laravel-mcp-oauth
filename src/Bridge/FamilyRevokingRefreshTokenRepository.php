<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Bridge;

use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Events\Dispatcher;
use Laravel\Passport\Bridge\RefreshTokenRepository;
use Laravel\Passport\Passport;
use Laravel\Passport\RefreshToken;
use Laravel\Passport\Token;
use Qiick\McpOAuth\Contracts\GrantStore;
use Qiick\McpOAuth\Data\RevocationReason;
use Qiick\McpOAuth\Events\McpRefreshTokenReused;

/**
 * Passport refresh-token bridge with atomic reuse detection (design §8.4).
 *
 * A successful rotation updates `revoked = false → true` (one row). Zero rows
 * means reuse or a race loser: the whole family (access + refresh + grant) is
 * revoked with {@see RevocationReason::Reuse}. {@see isRefreshTokenRevoked()}
 * also refuses a live refresh whose access token has no active bound grant
 * (S59), because League ignores the result of {@see revokeRefreshToken()}.
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
     * Atomic `WHERE revoked = false`. Zero affected rows → family revoke.
     */
    public function revokeRefreshToken(string $tokenId): void
    {
        $affectedRows = Passport::refreshToken()->newQuery()
            ->whereKey($tokenId)
            ->where('revoked', false)
            ->update(['revoked' => true]);

        if ($affectedRows === 0) {
            $this->revokeFamilyForRefreshToken($tokenId);
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

            return true;
        }

        $accessTokenId = $this->modelStringAttribute($refreshToken, 'access_token_id');

        if ($accessTokenId === null || ! $this->accessTokenHasActiveBoundGrant($accessTokenId)) {
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
            return;
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
            return;
        }

        $familyQuery = Passport::token()->newQuery()
            ->where('client_id', $clientId)
            ->where('user_id', $userIdentifier);

        if ($bindingValue === null) {
            $familyQuery->whereNull($bindingColumn);
        } else {
            $familyQuery->where($bindingColumn, $bindingValue);
        }

        $familyAccessTokenIds = [];

        foreach ($familyQuery->pluck('id') as $familyAccessTokenId) {
            if (is_string($familyAccessTokenId) && $familyAccessTokenId !== '') {
                $familyAccessTokenIds[] = $familyAccessTokenId;
            }
        }

        if ($familyAccessTokenIds === []) {
            $familyAccessTokenIds = [$accessTokenId];
        }

        $revokedTokenCount = 0;
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

        if ($accessToken === null || $this->modelAttributeIsTrue($accessToken, 'revoked')) {
            return false;
        }

        $bindingValue = $accessToken->getAttribute($this->bindingColumn());

        if ($bindingValue === null || $bindingValue === '') {
            return false;
        }

        $grantId = $this->grantIdFromBinding($bindingValue);

        if ($grantId === null) {
            return false;
        }

        $grant = $this->grantStore->find($grantId);

        return $grant !== null && ! $grant->revoked;
    }

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

    private function modelAttributeIsTrue(RefreshToken|Token $model, string $attribute): bool
    {
        return $model->getAttribute($attribute) === true;
    }

    private function modelStringAttribute(RefreshToken|Token $model, string $attribute): ?string
    {
        $value = $model->getAttribute($attribute);

        return is_string($value) && $value !== '' ? $value : null;
    }

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
