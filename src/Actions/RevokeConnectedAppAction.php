<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Actions;

use Carbon\CarbonInterface;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Database\SQLiteConnection;
use Laravel\Passport\Passport;
use Qiick\McpOAuth\Contracts\AuditLogger;
use Qiick\McpOAuth\Contracts\GrantStore;
use Qiick\McpOAuth\Data\GrantRecord;
use Qiick\McpOAuth\Data\RevocationReason;
use Qiick\McpOAuth\Events\McpGrantRevokedEvent;
use Qiick\McpOAuth\Internal\BoundedPositiveInt;
use Qiick\McpOAuth\Internal\PassportUserIdentifier;
use Qiick\McpOAuth\Models\OAuthClientMetadata;
use Qiick\McpOAuth\Models\OAuthConsentRecord;
use Throwable;

/**
 * Revokes a Connected apps grant at the user's request or the first use
 * of an expired installation. Its tokens and unexchanged authorization
 * codes are revoked so a credential already in flight cannot be used.
 *
 * Installation code bindings are revoked with the grant. For legacy clients,
 * the code's grant is inferred from time: only codes
 * issued before the revoke began (Passport writes `expires_at` as the issue
 * time plus the code TTL), and only while no newer grant is active for that
 * client and user. A newer consent already revoked the older codes when it
 * was approved, and its own code must survive (#49 review). A code issued in
 * the second the revoke began is kept: if it was the older grant's, its
 * exchange still fails (S54: a token for a revoked grant is revoked at once).
 *
 * Dispatches {@see McpGrantRevokedEvent}.
 *
 * @internal
 */
final class RevokeConnectedAppAction
{
    public function __construct(
        private readonly GrantStore $grantStore,
        private readonly RevokeGrantTokensAction $revokeGrantTokens,
        private readonly ConfigRepository $config,
        private readonly AuditLogger $auditLogger,
    ) {}

    public function execute(GrantRecord $grant, Authenticatable $user): void
    {
        $this->revoke($grant, $user, RevocationReason::User);
    }

    /** The caller has checked the absolute lifetime of this installation. */
    public function expire(GrantRecord $grant): void
    {
        $this->revoke($grant, null, RevocationReason::Expired);
    }

    private function revoke(GrantRecord $grant, ?Authenticatable $user, RevocationReason $reason): void
    {
        $actorIdentifier = $user === null ? null : PassportUserIdentifier::of($user);
        $revokeStartedAt = now()->startOfSecond();

        $authCodeTtlMinutes = BoundedPositiveInt::require(
            $this->config->get('mcp-oauth.auth_code_ttl_minutes'),
            'auth_code_ttl_minutes',
            BoundedPositiveInt::AUTH_CODE_TTL_MINUTES_MAX,
        );

        // One transaction on Passport's connection, holding the client's row
        // lock so two revokes of one grant run one after the other: the
        // second finds it no longer active and changes and records nothing.
        // The grant is written last, after the tokens, codes and audit entry
        // (AuditLogger): a failure before it leaves the grant active, even in
        // a GrantStore that commits on its own, and the revoke can be retried.
        // The event follows the commit, so listeners never hear of a revoke
        // that rolled back.
        $isGrantWriteStarted = false;

        try {
            $isRevoked = Passport::token()->getConnection()->transaction(function () use ($grant, $user, $actorIdentifier, $reason, $revokeStartedAt, $authCodeTtlMinutes, &$isGrantWriteStarted): bool {
                $metadata = OAuthClientMetadata::query()->where('client_id', $grant->clientId);

                if ($grant->installation !== null && $metadata->getConnection() instanceof SQLiteConnection) {
                    // SQLite needs a write lock before checking whether this installation is active.
                    $metadata->where('has_per_install_grants', true)->toBase()->update(['has_per_install_grants' => true]);
                }

                Passport::client()->newQuery()->whereKey($grant->clientId)->lockForUpdate()->first();

                if (! $this->hasActiveGrant($grant)) {
                    return false;
                }

                $this->revokeCredentialsAndRecord($grant, $user, $reason, $revokeStartedAt, $authCodeTtlMinutes);
                $isGrantWriteStarted = true;
                $this->grantStore->revoke($grant->id, $actorIdentifier, $reason);

                return true;
            });
        } catch (Throwable $transactionFailure) {
            // A GrantStore on a connection of its own committed the revoke,
            // then Passport's transaction failed (its commit): the grant cannot
            // be un-revoked, so its credentials and its one entry are written
            // again and the revoke completes. Anything else is rethrown untouched.
            if (! $isGrantWriteStarted || $this->hasActiveGrant($grant)) {
                throw $transactionFailure;
            }

            app(ExceptionHandler::class)->report($transactionFailure);
            Passport::token()->getConnection()->transaction(fn () => $this->revokeCredentialsAndRecord($grant, $user, $reason, $revokeStartedAt, $authCodeTtlMinutes));
            $isRevoked = true;
        }

        if ($isRevoked) {
            event(new McpGrantRevokedEvent($grant->id, $grant->clientId, $grant->userIdentifier, $actorIdentifier, $reason, $grant->installation?->installId));
        }
    }

    private function hasActiveGrant(GrantRecord $grant): bool
    {
        return $grant->installation === null
            ? $this->grantStore->activeFor($grant->clientId, $grant->userIdentifier)?->id === $grant->id
            : $this->grantStore->find($grant->id)?->revoked === false;
    }

    /**
     * The grant's tokens and unexchanged codes, and its audit entry: every
     * write of the revoke except the grant's own.
     */
    private function revokeCredentialsAndRecord(GrantRecord $grant, ?Authenticatable $user, RevocationReason $reason, CarbonInterface $revokeStartedAt, int $authCodeTtlMinutes): void
    {
        $this->revokeGrantTokens->execute($grant);
        if ($grant->installation === null) {
            // Legacy codes are inferred from the client, user and issue time.
            Passport::authCode()->newQuery()
                ->where('client_id', $grant->clientId)
                ->where('user_id', $grant->userIdentifier)
                ->where('expires_at', '<', $revokeStartedAt->copy()->addMinutes($authCodeTtlMinutes))
                ->update(['revoked' => true]);
        }

        $this->auditLogger->record('oauth_grant_revoked', $user, $grant->id, [
            'client_id' => $grant->clientId,
            'redirect_host' => OAuthConsentRecord::redirectHostOfGrant($grant->id),
            'reason' => $reason->value,
            ...($grant->installation === null ? [] : ['install_id' => $grant->installation->installId]),
        ]);
    }
}
