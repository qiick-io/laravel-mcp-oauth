<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Actions;

use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Database\ConnectionInterface;
use Illuminate\Http\Request;
use Laravel\Passport\Passport;
use Qiick\McpOAuth\Contracts\ConsentProvider;
use Qiick\McpOAuth\Contracts\GrantStore;
use Qiick\McpOAuth\Data\PendingAuthorizationRequestData;
use Qiick\McpOAuth\Events\McpConsentApproved;
use Qiick\McpOAuth\Internal\PassportUserIdentifier;
use Qiick\McpOAuth\Services\ConsentDecisionService;
use Qiick\McpOAuth\Services\ConsentPageService;
use Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException;

/**
 * The signed-in user approved the client on the consent screen (design §8.3
 * step 4, S46–S48, S52):
 *
 * 1. `canGrant` false is a 403 (the client was re-read by
 *    PendingAuthorizationRequestService);
 * 2. the posted choices become a ConsentDecision judged against the offered
 *    options, then by ConsentProvider::validate();
 * 3. in one transaction: GrantStore::replace() (the earlier grant is revoked
 *    by the product), every earlier auth code, access token and refresh token
 *    of this client and user is revoked, so an unexchanged old code cannot be
 *    bound to the new grant, and the consent record is written;
 * 4. McpConsentApproved is dispatched after the commit;
 * 5. the request is marked approved, ready for
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

        $redirectUri = $authorizationRequest->getRedirectUri() ?? $clientInfo->redirectUris[0];
        $userIdentifier = PassportUserIdentifier::of($user);
        $decision = $this->consentDecisions->fromRequest($request, $consentOptions, $clientInfo->id, $userIdentifier, $redirectUri);

        $this->consentProvider->validate($request, $user, $decision);

        $grant = $this->database->transaction(function () use ($request, $pendingAuthorizationRequest, $redirectUri, $decision, $clientInfo, $userIdentifier) {
            $grant = $this->grantStore->replace($decision);
            $this->revokeEarlierCredentials($clientInfo->id, $userIdentifier);
            $this->recordConsentDecision->execute($request, $pendingAuthorizationRequest, $redirectUri, $decision, $grant);

            return $grant;
        });

        $this->events->dispatch(new McpConsentApproved(
            clientId: $clientInfo->id,
            userIdentifier: $userIdentifier,
            grantId: $grant->id,
            redirectHost: $clientInfo->redirectHost,
            scopes: $decision->scopes,
            resources: $decision->resources,
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
