<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Services;

use Illuminate\Http\Request;
use Laravel\Passport\Bridge\Client as BridgeClient;
use Laravel\Passport\Bridge\Scope as BridgeScope;
use Laravel\Passport\Bridge\User as BridgeUser;
use Laravel\Passport\Client;
use Laravel\Passport\Passport;
use League\OAuth2\Server\RequestTypes\AuthorizationRequest;
use League\OAuth2\Server\RequestTypes\AuthorizationRequestInterface;
use Qiick\McpOAuth\Data\PendingAuthorizationRequestData;
use Qiick\McpOAuth\Internal\PassportUserIdentifier;
use Qiick\McpOAuth\RedirectUriGuard;
use Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException;

/**
 * The authorization request the consent page was rendered for, as Passport
 * left it in the session (`authToken`, `authRequest`), design §8.3 step 4
 * and S45.
 *
 * Approve and deny accept it only when the posted `auth_token` matches the
 * session one, the request belongs to the signed-in user, and its client is
 * still active and unblocked. Anything else is a 403 that never redirects,
 * so a stale or forged form cannot send the browser to the client.
 */
final class PendingAuthorizationRequestService
{
    public function __construct(
        private readonly RedirectUriGuard $redirectUriGuard,
    ) {}

    /**
     * Reads the pending request without consuming it, so a validation error
     * lets the user correct the form and post again.
     *
     * @throws AccessDeniedHttpException
     */
    public function peek(Request $request): PendingAuthorizationRequestData
    {
        $session = $request->session();
        $sessionAuthToken = $session->get('authToken');
        $postedAuthToken = $request->input('auth_token');

        if (! is_string($sessionAuthToken) || ! is_string($postedAuthToken) || ! hash_equals($sessionAuthToken, $postedAuthToken)) {
            $this->refuse($request);
        }

        $serializedAuthorizationRequest = $session->get('authRequest');
        $authorizationRequest = is_string($serializedAuthorizationRequest)
            ? unserialize($serializedAuthorizationRequest, ['allowed_classes' => [
                AuthorizationRequest::class,
                BridgeClient::class,
                BridgeScope::class,
                BridgeUser::class,
            ]])
            : null;

        if (! $authorizationRequest instanceof AuthorizationRequestInterface) {
            $this->refuse($request);
        }

        $signedInUser = $request->user();
        $pendingUser = $authorizationRequest->getUser();

        if ($signedInUser === null || $pendingUser === null || $pendingUser->getIdentifier() !== PassportUserIdentifier::of($signedInUser)) {
            $this->refuse($request);
        }

        // Re-read so a revoke or a host block after the consent page takes effect.
        $client = Passport::client()->newQuery()
            ->whereKey($authorizationRequest->getClient()->getIdentifier())
            ->where('revoked', false)
            ->first();

        if (! $client instanceof Client || $this->redirectUriGuard->clientHasBlockedRedirectHost($client)) {
            $this->refuse($request);
        }

        return new PendingAuthorizationRequestData($authorizationRequest, $client, $signedInUser);
    }

    /**
     * Consumes the pending request once the decision is recorded, so the same
     * form cannot be replayed.
     */
    public function forget(Request $request): void
    {
        $request->session()->forget(['authToken', 'authRequest']);
    }

    /**
     * @throws AccessDeniedHttpException
     */
    private function refuse(Request $request): never
    {
        $this->forget($request);

        throw new AccessDeniedHttpException('There is no pending authorization request for this user.');
    }
}
