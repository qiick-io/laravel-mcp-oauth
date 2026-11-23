<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Bridge;

use Laravel\Passport\AuthCode;
use Laravel\Passport\Bridge\AuthCodeRepository;
use Laravel\Passport\Passport;
use Qiick\McpOAuth\Actions\RevokeAuthCodeTokensAction;
use Qiick\McpOAuth\Contracts\GrantStore;
use Qiick\McpOAuth\Models\OAuthAuthCodeExchange;

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
 */
final class OneShotAuthCodeRepository extends AuthCodeRepository
{
    public function __construct(
        private readonly GrantStore $grantStore,
        private readonly RevokeAuthCodeTokensAction $revokeAuthCodeTokens,
    ) {}

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

            $this->recordGrantOf($codeId);

            return true;
        });

        if ($isFirstPresentation) {
            return false;
        }

        $this->revokeAuthCodeTokens->execute($codeId);

        return true;
    }

    /**
     * The grant BindAccessTokenAction will bind this exchange's tokens to:
     * the active grant of the code's client and user.
     */
    private function recordGrantOf(string $codeId): void
    {
        /** @var AuthCode $authCode the row the update above just consumed */
        $authCode = Passport::authCode()->newQuery()->findOrFail($codeId);

        /** @var array{client_id: string, user_id: int|string} $codeOwner Passport writes both when it persists a code */
        $codeOwner = $authCode->only(['client_id', 'user_id']);
        $grant = $this->grantStore->activeFor($codeOwner['client_id'], (string) $codeOwner['user_id']);

        if ($grant !== null) {
            OAuthAuthCodeExchange::query()->create(['auth_code_id' => $codeId, 'grant_id' => $grant->id]);
        }
    }
}
