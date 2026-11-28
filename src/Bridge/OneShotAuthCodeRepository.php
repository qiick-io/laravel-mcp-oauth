<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Bridge;

use Laravel\Passport\AuthCode;
use Laravel\Passport\Bridge\AuthCodeRepository;
use Laravel\Passport\Passport;
use League\OAuth2\Server\Entities\AuthCodeEntityInterface;
use LogicException;
use Qiick\McpOAuth\Actions\RevokeAuthCodeTokensAction;
use Qiick\McpOAuth\Contracts\GrantStore;
use Qiick\McpOAuth\Data\GrantInstallationData;
use Qiick\McpOAuth\Data\GrantRecord;
use Qiick\McpOAuth\Internal\ConsumedAuthCodeGrant;
use Qiick\McpOAuth\Models\OAuthAuthCodeExchange;
use Qiick\McpOAuth\Models\OAuthClientMetadata;

/**
 * Passport auth-code bridge that makes every code one-shot (RFC 9700 §4.5,
 * OAuth 2.1 §4.1.3).
 *
 * League asks {@see isAuthCodeRevoked()} once per exchange, after the expiry
 * check and before it compares the client, the redirect URI and the PKCE
 * verifier. That call now consumes the code with an atomic
 * `UPDATE … WHERE revoked = false`, so:
 *
 * - a failed attempt (wrong verifier, redirect URI or client) burns the code,
 *   and the right verifier cannot follow;
 * - of two parallel exchanges only one wins, which league alone leaves open;
 * - the grant the code is consumed under is recorded, and a later
 *   presentation revokes the tokens issued with it
 *   ({@see RevokeAuthCodeTokensAction}).
 *
 * @internal
 */
final class OneShotAuthCodeRepository extends AuthCodeRepository
{
    public function __construct(
        private readonly GrantStore $grantStore,
        private readonly RevokeAuthCodeTokensAction $revokeAuthCodeTokens,
        private readonly ConsumedAuthCodeGrant $consumedAuthCodeGrant,
    ) {}

    /** Persists a per-install code and its exact grant in one Passport transaction. */
    public function persistNewAuthCode(AuthCodeEntityInterface $authCodeEntity): void
    {
        $grant = request()->attributes->get(GrantInstallationData::APPROVED_GRANT_ATTRIBUTE);

        if (! $grant instanceof GrantRecord) {
            parent::persistNewAuthCode($authCodeEntity);

            return;
        }

        if ($grant->clientId !== $authCodeEntity->getClient()->getIdentifier()
            || $grant->userIdentifier !== $authCodeEntity->getUserIdentifier()) {
            throw new LogicException('The authorization code does not belong to the approved installation.');
        }

        Passport::authCode()->getConnection()->transaction(function () use ($authCodeEntity, $grant): void {
            parent::persistNewAuthCode($authCodeEntity);
            OAuthAuthCodeExchange::query()->create([
                'auth_code_id' => $authCodeEntity->getIdentifier(),
                'grant_id' => $grant->id,
                'user_identifier' => $grant->userIdentifier,
                'expires_at' => $authCodeEntity->getExpiryDateTime(),
            ]);
        });
    }

    /**
     * {@inheritdoc}
     *
     * True for a missing or already used code (and its tokens are revoked);
     * false once, for the presentation that consumes it.
     */
    public function isAuthCodeRevoked(string $codeId): bool
    {
        $isFirstPresentation = Passport::authCode()->getConnection()->transaction(function () use ($codeId): bool {
            $consumedRows = Passport::authCode()->newQuery()
                ->whereKey($codeId)
                ->where('revoked', false)
                ->update(['revoked' => true]);

            if ($consumedRows === 0) {
                return false;
            }

            return $this->recordGrantOf($codeId);
        });

        if ($isFirstPresentation) {
            return false;
        }

        $this->revokeAuthCodeTokens->execute($codeId);

        return true;
    }

    /**
     * The grant this exchange's token is bound to (BindAccessTokenAction,
     * through ConsumedAuthCodeGrant) and a replay revokes: the active grant of
     * the code's client and user at the moment the code is consumed, or the
     * exact installation granted when an opted-in client's code was issued.
     */
    private function recordGrantOf(string $codeId): bool
    {
        /** @var AuthCode $authCode the row the update above just consumed */
        $authCode = Passport::authCode()->newQuery()->findOrFail($codeId);

        /** @var array{client_id: string, user_id: int|string} $codeOwner Passport writes both when it persists a code */
        $codeOwner = $authCode->only(['client_id', 'user_id']);
        $userIdentifier = (string) $codeOwner['user_id'];
        $exchange = OAuthAuthCodeExchange::query()->find($codeId);

        if ($exchange !== null) {
            $grant = $this->grantStore->find($exchange->grant_id);

            if ($exchange->expires_at === null || $grant === null || $grant->revoked || $grant->installation === null
                || $grant->clientId !== $codeOwner['client_id'] || $grant->userIdentifier !== $userIdentifier
                || ! OAuthClientMetadata::isPerInstallClient($grant->clientId)) {
                return false;
            }

            $exchange->update(['expires_at' => null]);
            $this->consumedAuthCodeGrant->record($grant->id);

            return true;
        }

        if (OAuthClientMetadata::isPerInstallClient($codeOwner['client_id'])) {
            return false;
        }

        $grant = $this->grantStore->activeFor($codeOwner['client_id'], $userIdentifier);

        $this->consumedAuthCodeGrant->record($grant?->id);

        if ($grant !== null) {
            OAuthAuthCodeExchange::query()->create([
                'auth_code_id' => $codeId,
                'grant_id' => $grant->id,
                'user_identifier' => $userIdentifier,
            ]);
        }

        return true;
    }
}
