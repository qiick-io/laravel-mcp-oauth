<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Actions;

use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Database\ConnectionInterface;
use Illuminate\Database\SQLiteConnection;
use Illuminate\Http\Request;
use Laravel\Passport\Passport;
use LogicException;
use Qiick\McpOAuth\Contracts\AuditLogger;
use Qiick\McpOAuth\Contracts\ConsentProvider;
use Qiick\McpOAuth\Contracts\GrantStore;
use Qiick\McpOAuth\Contracts\InstallationGrantStoreContract;
use Qiick\McpOAuth\Data\ConsentDecision;
use Qiick\McpOAuth\Data\GrantInstallationData;
use Qiick\McpOAuth\Data\GrantRecord;
use Qiick\McpOAuth\Data\PendingAuthorizationRequestData;
use Qiick\McpOAuth\Events\McpConsentApprovedEvent;
use Qiick\McpOAuth\Internal\PassportUserIdentifier;
use Qiick\McpOAuth\Models\OAuthClientMetadata;
use Qiick\McpOAuth\Services\ConsentDecisionService;
use Qiick\McpOAuth\Services\ConsentPageService;
use Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException;
use Symfony\Component\HttpKernel\Exception\ConflictHttpException;

/**
 * The signed-in user approved the client on the consent screen (design §8.3
 * step 4, S46–S48, S52):
 *
 * 1. `canGrant` false is a 403 (the client was re-read by
 *    PendingAuthorizationRequestService);
 * 2. a consent text version other than the rendered page's is a 409: the
 *    user must see the current text before it is recorded as accepted;
 * 3. the posted choices become a ConsentDecision judged against the offered
 *    options, then by ConsentProvider::validate();
 * 4. in one transaction, holding the client's metadata row lock (a client
 *    pruned meanwhile is refused): GrantStore::replace() (the earlier grant is revoked
 *    by the product), the earlier auth codes, access tokens and refresh tokens
 *    are revoked, the consent record is written, and the client
 *    is marked authorised the first time (`first_authorized_at`, which
 *    keeps mcp-oauth:prune-unused-clients off it after the grant is purged);
 * 5. McpConsentApprovedEvent is dispatched after the commit;
 * 6. the request is marked approved, ready for
 *    AuthorizationResponseService::complete().
 *
 * For installation grants, replacement and credential revocation are scoped
 * to the exact installation and organisation. The code carries that binding
 * when Passport persists it.
 *
 * @internal
 */
final class ApproveConsentAction
{
    public function __construct(
        private readonly ConsentPageService $consentPages,
        private readonly ConsentDecisionService $consentDecisions,
        private readonly ConsentProvider $consentProvider,
        private readonly GrantStore $grantStore,
        private readonly RecordConsentDecisionAction $recordConsentDecision,
        private readonly RevokeGrantTokensAction $revokeGrantTokens,
        private readonly ConnectionInterface $database,
        private readonly Dispatcher $events,
        private readonly AuditLogger $auditLogger,
    ) {}

    /**
     * @throws AccessDeniedHttpException when the user may not grant anything
     * @throws ConflictHttpException when the consent text changed after the page was rendered
     */
    public function execute(Request $request, PendingAuthorizationRequestData $pendingAuthorizationRequest): void
    {
        $user = $pendingAuthorizationRequest->user;
        $authorizationRequest = $pendingAuthorizationRequest->authorizationRequest;
        $clientInfo = $this->consentPages->clientInfo($pendingAuthorizationRequest->client, $authorizationRequest->getRedirectUri());
        $consentOptions = $this->consentProvider->options($request, $user, $clientInfo);

        if (! $consentOptions->canGrant) {
            throw new AccessDeniedHttpException('You may not grant access to this client.');
        }

        if ($consentOptions->consentVersion !== $pendingAuthorizationRequest->renderedConsentVersion) {
            throw new ConflictHttpException('The consent text changed after this page was shown. Start the authorization again.');
        }

        $redirectUri = $authorizationRequest->getRedirectUri() ?? $clientInfo->redirectUris[0];
        $userIdentifier = PassportUserIdentifier::of($user);
        $decision = $this->consentDecisions->fromRequest($request, $consentOptions, $pendingAuthorizationRequest, $clientInfo->id, $userIdentifier, $redirectUri);

        $this->consentProvider->validate($request, $user, $decision);

        // The client's metadata row is locked on its own (Passport's)
        // connection for the whole approval: the same lock
        // mcp-oauth:prune-unused-clients takes before it deletes. A prune that
        // committed first leaves no row and the approval is refused; one that
        // comes later sees first_authorized_at and keeps the client. On one
        // connection the inner transaction is a savepoint.
        /** @var GrantRecord $grant Laravel 12 types transaction() as mixed */
        $grant = OAuthClientMetadata::query()->getConnection()->transaction(fn (): mixed => $this->database->transaction(function () use ($request, $pendingAuthorizationRequest, $redirectUri, $decision, $clientInfo, $userIdentifier, $user): GrantRecord {
            $metadata = OAuthClientMetadata::query()->where('client_id', $clientInfo->id);

            if ($decision->installation !== null && $metadata->getConnection() instanceof SQLiteConnection) {
                // SQLite ignores FOR UPDATE. Acquire its write lock before reading,
                // so two deferred transactions cannot both read then try to upgrade.
                (clone $metadata)->where('has_per_install_grants', true)->toBase()->update(['has_per_install_grants' => true]);
            }

            $isStillRegistered = $metadata->lockForUpdate()->exists();

            if (! $isStillRegistered) {
                throw new AccessDeniedHttpException('This client is no longer registered.');
            }

            $grant = $decision->installation === null ? $this->grantStore->replace($decision) : $this->replaceInstallation($decision);

            if ($decision->resourceScopes !== []) {
                // JSON storage can reorder object keys. Compare the pairs
                // strictly without imposing the browser's iteration order.
                $approvedResourceScopes = $decision->resourceScopes;
                $storedResourceScopes = $grant->resourceScopes;
                ksort($approvedResourceScopes);
                ksort($storedResourceScopes);

                if ($storedResourceScopes !== $approvedResourceScopes) {
                    throw new LogicException('The GrantStore must preserve the approved resource scopes.');
                }
            }

            if ($decision->installation === null) {
                $this->revokeEarlierCredentials($clientInfo->id, $userIdentifier);
            }
            $this->recordConsentDecision->execute($request, $pendingAuthorizationRequest, $redirectUri, $decision, $grant);
            OAuthClientMetadata::query()
                ->where('client_id', $clientInfo->id)
                ->whereNull('first_authorized_at')
                ->update(['first_authorized_at' => now()]);
            $this->auditLogger->record('oauth_consent_approved', $user, $grant->id, [
                'client_id' => $clientInfo->id,
                'redirect_host' => $clientInfo->redirectHost,
                'scopes' => $decision->scopes,
                'resources' => $decision->resources,
                ...($grant->installation === null ? [] : ['install_id' => $grant->installation->installId]),
            ]);

            return $grant;
        }));

        $this->events->dispatch(new McpConsentApprovedEvent(
            clientId: $clientInfo->id,
            userIdentifier: $userIdentifier,
            grantId: $grant->id,
            redirectHost: $clientInfo->redirectHost,
            scopes: $decision->scopes,
            resources: $decision->resources,
            resource: $decision->resource,
            resourceScopes: $decision->resourceScopes,
            installId: $grant->installation?->installId,
        ));

        if ($decision->installation !== null) {
            $request->attributes->set(GrantInstallationData::APPROVED_GRANT_ATTRIBUTE, $grant);
        }

        $authorizationRequest->setAuthorizationApproved(true);
    }

    private function replaceInstallation(ConsentDecision $decision): GrantRecord
    {
        $installation = $decision->installation;

        if ($installation === null || ! OAuthClientMetadata::isPerInstallClient($decision->clientId)) {
            throw new AccessDeniedHttpException('This client can no longer authorize an installation.');
        }

        if (! $this->grantStore instanceof InstallationGrantStoreContract) {
            throw new LogicException('Per-install grants require InstallationGrantStoreContract.');
        }

        $replacement = $this->grantStore->replaceForInstallation($decision);
        $grant = $replacement->grant;

        if ($grant->revoked || $grant->clientId !== $decision->clientId || $grant->userIdentifier !== $decision->userIdentifier
            || $grant->authorizedAt === null || $grant->installation === null
            || ! $grant->installation->hasSameAccountAs($installation)
            || $grant->installation->keyThumbprint !== $installation->keyThumbprint) {
            throw new LogicException('The GrantStore must preserve the authorized installation and consent time.');
        }

        $priorGrant = $replacement->previousGrant;

        if ($priorGrant !== null) {
            if ($priorGrant->id === $grant->id || $priorGrant->clientId !== $decision->clientId || $priorGrant->userIdentifier !== $decision->userIdentifier
                || $priorGrant->installation === null || ! $priorGrant->installation->hasSameAccountAs($installation)) {
                throw new LogicException('The GrantStore must return the distinct previous grant for this account.');
            }

            $this->revokeGrantTokens->execute($priorGrant);
        }

        return $grant;
    }

    private function revokeEarlierCredentials(string $clientId, string $userIdentifier): void
    {
        Passport::authCode()->newQuery()
            ->where('client_id', $clientId)
            ->where('user_id', $userIdentifier)
            ->update(['revoked' => true]);

        $accessTokens = Passport::token()->newQuery()
            ->where('client_id', $clientId)
            ->where('user_id', $userIdentifier);

        Passport::refreshToken()->newQuery()
            ->whereIn('access_token_id', (clone $accessTokens)->select('id'))
            ->update(['revoked' => true]);

        $accessTokens->update(['revoked' => true]);
    }
}
