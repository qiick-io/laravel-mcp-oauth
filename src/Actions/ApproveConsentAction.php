<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Actions;

use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Database\ConnectionInterface;
use Illuminate\Http\Request;
use Laravel\Passport\Passport;
use Qiick\McpOAuth\Contracts\ConsentProvider;
use Qiick\McpOAuth\Contracts\GrantStore;
use Qiick\McpOAuth\Data\GrantRecord;
use Qiick\McpOAuth\Data\PendingAuthorizationRequestData;
use Qiick\McpOAuth\Events\McpConsentApproved;
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
 *    by the product), every earlier auth code, access token and refresh token
 *    of this client and user is revoked, so an unexchanged old code cannot be
 *    bound to the new grant, the consent record is written, and the client
 *    is marked authorised the first time (`first_authorized_at`, which
 *    keeps mcp-oauth:prune-unused-clients off it after the grant is purged);
 * 5. McpConsentApproved is dispatched after the commit;
 * 6. the request is marked approved, ready for
 *    AuthorizationResponseService::complete().
 */
final class ApproveConsentAction
{
    public function __construct(
        private readonly ConsentPageService $consentPages,
        private readonly ConsentDecisionService $consentDecisions,
        private readonly ConsentProvider $consentProvider,
        private readonly GrantStore $grantStore,
        private readonly RecordConsentDecisionAction $recordConsentDecision,
        private readonly ConnectionInterface $database,
        private readonly Dispatcher $events,
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
        $grant = OAuthClientMetadata::query()->getConnection()->transaction(fn (): mixed => $this->database->transaction(function () use ($request, $pendingAuthorizationRequest, $redirectUri, $decision, $clientInfo, $userIdentifier): GrantRecord {
            $isStillRegistered = OAuthClientMetadata::query()->where('client_id', $clientInfo->id)->lockForUpdate()->exists();

            if (! $isStillRegistered) {
                throw new AccessDeniedHttpException('This client is no longer registered.');
            }

            $grant = $this->grantStore->replace($decision);
            $this->revokeEarlierCredentials($clientInfo->id, $userIdentifier);
            $this->recordConsentDecision->execute($request, $pendingAuthorizationRequest, $redirectUri, $decision, $grant);
            OAuthClientMetadata::query()
                ->where('client_id', $clientInfo->id)
                ->whereNull('first_authorized_at')
                ->update(['first_authorized_at' => now()]);

            return $grant;
        }));

        $this->events->dispatch(new McpConsentApproved(
            clientId: $clientInfo->id,
            userIdentifier: $userIdentifier,
            grantId: $grant->id,
            redirectHost: $clientInfo->redirectHost,
            scopes: $decision->scopes,
            resources: $decision->resources,
            resource: $decision->resource,
        ));

        // The wire scopes are already exactly `mcp:use`: the authorization
        // request middleware dropped the requested scope, so league applied
        // Passport's default.
        $authorizationRequest->setAuthorizationApproved(true);
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
