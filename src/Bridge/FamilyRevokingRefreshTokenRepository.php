<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Bridge;

use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Support\Facades\Log;
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
 * issuance the same way. Client-facing hints stay opaque (same as League’s
 * “Token has been revoked”); path details go to logs and audit events only.
 * {@see isRefreshTokenRevoked()} also refuses a live refresh whose access
 * token has no active bound grant (S59).
 */
final class FamilyRevokingRefreshTokenRepository extends RefreshTokenRepository
{
    /**
     * Opaque hint shared by every invalid_grant from this repository (and
     * aligned with League’s revoked-refresh path). Distinct hints would let
     * a client tell reuse apart from concurrent family revoke.
     */
    private const string CLIENT_INVALID_REFRESH_HINT = 'Token has been revoked';

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
        // The conditional UPDATE is the compare-and-set: a concurrent rotator
        // waits on the row lock the winner's UPDATE holds, then re-reads the
        // row and matches nothing (PostgreSQL READ COMMITTED, InnoDB's
        // locking read; SQLite serialises writers), or fails with a
        // serialisation error under PostgreSQL REPEATABLE READ. Either way at
        // most one rotation succeeds, so no separate lock is taken.
        $affectedRows = Passport::refreshToken()->newQuery()
            ->whereKey($tokenId)
            ->where('revoked', false)
            ->update(['revoked' => true]);

        if ($affectedRows === 0) {
            $this->revokeFamilyForRefreshToken($tokenId);
            Log::warning('MCP OAuth refresh refused: reuse or race (CAS miss).');

            throw OAuthServerException::invalidRefreshToken(self::CLIENT_INVALID_REFRESH_HINT);
        }

        // League revokes the old access token before this call; when a binding
        // is present, only the grant status tells us a concurrent loser already
        // ran family revoke. Unbound tokens skip this (binding listener PR).
        $grantId = $this->grantIdFromBinding(
            $this->accessTokenForRefreshToken($tokenId)?->getAttribute($this->bindingColumn()),
        );

        if ($grantId !== null && ! $this->grantIsActive($grantId)) {
            Log::warning('MCP OAuth refresh refused: bound grant already revoked.');

            throw OAuthServerException::invalidRefreshToken(self::CLIENT_INVALID_REFRESH_HINT);
        }
    }

    /**
     * {@inheritdoc}
     *
     * Missing → true. Already revoked, or an access token without an active
     * bound grant (S59) → family revoke, then true.
     */
    public function isRefreshTokenRevoked(string $tokenId): bool
    {
        /** @var RefreshToken|null $refreshToken */
        $refreshToken = Passport::refreshToken()->newQuery()->whereKey($tokenId)->first();

        if ($refreshToken === null) {
            return true;
        }

        if ($refreshToken->getAttribute('revoked') === true
            || ! $this->accessTokenHasActiveBoundGrant($refreshToken->getAttribute('access_token_id'))) {
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

        $accessTokenId = $refreshToken->getAttribute('access_token_id');

        // Passport's column is not null, but a custom refresh-token model may
        // allow it: `where(..., null)` would become `whereNull` and revoke the
        // orphaned refresh tokens of every user.
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
        /** @var string $clientId non-null uuid column in Passport's schema */
        $clientId = $accessToken->getAttribute('client_id');
        /** @var int|string|null $userIdentifier */
        $userIdentifier = $accessToken->getAttribute('user_id');

        $familyQuery = Passport::token()->newQuery()
            ->where('client_id', $clientId)
            ->where('user_id', $userIdentifier);

        if ($bindingValue === null) {
            $familyQuery->whereNull($bindingColumn);
        } else {
            $familyQuery->where($bindingColumn, $bindingValue);
        }

        // The access token matches its own family query, so the list is never empty.
        $familyAccessTokenIds = $familyQuery->pluck('id')->all();

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
            $eventUserIdentifier = (string) $userIdentifier;

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
     * S59: refresh is usable only while its access token is live and carries
     * a binding to a grant that {@see GrantStore::find()} still reports as
     * not revoked.
     */
    private function accessTokenHasActiveBoundGrant(mixed $accessTokenId): bool
    {
        /** @var Token|null $accessToken */
        $accessToken = Passport::token()->newQuery()->whereKey($accessTokenId)->first();

        if ($accessToken === null || $accessToken->getAttribute('revoked') === true) {
            return false;
        }

        $grantId = $this->grantIdFromBinding($accessToken->getAttribute($this->bindingColumn()));

        return $grantId !== null && $this->grantIsActive($grantId);
    }

    /**
     * Only called after a CAS win, so the refresh token row exists.
     */
    private function accessTokenForRefreshToken(string $refreshTokenId): ?Token
    {
        $accessTokenId = Passport::refreshToken()->newQuery()->whereKey($refreshTokenId)->value('access_token_id');

        /** @var Token|null $accessToken */
        $accessToken = Passport::token()->newQuery()->whereKey($accessTokenId)->first();

        return $accessToken;
    }

    private function grantIsActive(string $grantId): bool
    {
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
     * the grant's public UUID, or an integer key).
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
}
