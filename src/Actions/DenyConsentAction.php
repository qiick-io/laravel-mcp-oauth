<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Actions;

use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Http\Request;
use Qiick\McpOAuth\Data\PendingAuthorizationRequestData;
use Qiick\McpOAuth\Events\McpConsentDenied;
use Qiick\McpOAuth\Internal\PassportUserIdentifier;
use Qiick\McpOAuth\Services\ConsentPageService;

/**
 * The signed-in user denied the client (design §8.3 step 5, S50): no grant
 * and no credential change, one `denied` consent record kept 90 days so a
 * refused phishing attempt leaves evidence (standards review decision 5),
 * McpConsentDenied, and the request marked denied so league answers
 * `access_denied` to the client.
 */
final class DenyConsentAction
{
    public function __construct(
        private readonly ConsentPageService $consentPages,
        private readonly RecordConsentDecisionAction $recordConsentDecision,
        private readonly Dispatcher $events,
    ) {}

    public function execute(Request $request, PendingAuthorizationRequestData $pendingAuthorizationRequest): void
    {
        $authorizationRequest = $pendingAuthorizationRequest->authorizationRequest;
        $clientInfo = $this->consentPages->clientInfo($pendingAuthorizationRequest->client, $authorizationRequest->getRedirectUri());
        $redirectUri = $authorizationRequest->getRedirectUri() ?? $clientInfo->redirectUris[0];

        $this->recordConsentDecision->execute($request, $pendingAuthorizationRequest, $redirectUri, null, null);

        $this->events->dispatch(new McpConsentDenied(
            clientId: $clientInfo->id,
            userIdentifier: PassportUserIdentifier::of($pendingAuthorizationRequest->user),
        ));

        // League's AuthorizationRequest starts unapproved, so completing it
        // now answers access_denied.
    }
}
