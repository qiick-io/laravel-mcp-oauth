<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Http\Controllers;

use Illuminate\Http\Request;
use Qiick\McpOAuth\Actions\ApproveConsentAction;
use Qiick\McpOAuth\Services\AuthorizationResponseService;
use Qiick\McpOAuth\Services\PendingAuthorizationRequestService;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Exception\ConflictHttpException;

/**
 * `POST oauth/authorize` (web, auth, verified; CSRF from the web group): the
 * user approved. The pending request is consumed only after the approval is
 * recorded, so a validation error leaves the form usable.
 */
final class ApproveClientController
{
    public function __construct(
        private readonly PendingAuthorizationRequestService $pendingAuthorizationRequests,
        private readonly ApproveConsentAction $approveConsent,
        private readonly AuthorizationResponseService $authorizationResponses,
    ) {}

    public function __invoke(Request $request): Response
    {
        $pendingAuthorizationRequest = $this->pendingAuthorizationRequests->peek($request);

        try {
            $this->approveConsent->execute($request, $pendingAuthorizationRequest);
        } catch (ConflictHttpException $consentTextChanged) {
            // A stale page cannot be approved later either.
            $this->pendingAuthorizationRequests->forget($request);

            throw $consentTextChanged;
        }

        $this->pendingAuthorizationRequests->forget($request);

        return $this->authorizationResponses->complete($request, $pendingAuthorizationRequest->authorizationRequest);
    }
}
