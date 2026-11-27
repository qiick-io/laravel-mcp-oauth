<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Http\Controllers;

use Illuminate\Http\Request;
use Qiick\McpOAuth\Actions\DenyConsentAction;
use Qiick\McpOAuth\Services\AuthorizationResponseService;
use Qiick\McpOAuth\Services\PendingAuthorizationRequestService;
use Symfony\Component\HttpFoundation\Response;

/**
 * `DELETE oauth/authorize` (web, auth, verified; CSRF from the web group):
 * the user denied. The client receives `access_denied` with `state` and `iss`.
 *
 * @internal
 */
final class DenyClientController
{
    public function __construct(
        private readonly PendingAuthorizationRequestService $pendingAuthorizationRequests,
        private readonly DenyConsentAction $denyConsent,
        private readonly AuthorizationResponseService $authorizationResponses,
    ) {}

    public function __invoke(Request $request): Response
    {
        $pendingAuthorizationRequest = $this->pendingAuthorizationRequests->peek($request);

        $this->denyConsent->execute($request, $pendingAuthorizationRequest);
        $this->pendingAuthorizationRequests->forget($request);

        return $this->authorizationResponses->complete($request, $pendingAuthorizationRequest->authorizationRequest);
    }
}
