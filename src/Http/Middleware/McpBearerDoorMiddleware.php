<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Http\Middleware;

use Closure;
use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Container\Container;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\RateLimiter;
use Qiick\McpOAuth\AccessTokenAuthenticator;
use Qiick\McpOAuth\ClientThrottleKey;
use Qiick\McpOAuth\Contracts\ApiKeyDoor;
use Qiick\McpOAuth\Contracts\McpCredentialBinder;
use Qiick\McpOAuth\Data\AuthorizationDecision;
use Qiick\McpOAuth\Internal\BoundedPositiveInt;
use Qiick\McpOAuth\McpOAuthServer;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Exception\HttpExceptionInterface;

/**
 * The `/mcp` Bearer door (design §5.3): one selection algorithm for the
 * product's API keys and the package's OAuth tokens, placed where a product
 * authenticates `/mcp`, before its own throttle:
 *
 * 1. the per-address failure brake answers 429 before the credential is read;
 * 2. no Bearer: 401 (McpChallengeMiddleware asks for credentials);
 * 3. an API-key-shaped Bearer goes to the product's ApiKeyDoor;
 * 4. OAuth on without usable Passport keys: 503 `temporarily_unavailable`;
 * 5. OAuth ready: AccessTokenAuthenticator, then the grant is bound;
 * 6. OAuth off: the token goes to the ApiKeyDoor, an unknown API key as before.
 *
 * Every 401 and 403, the product's included, counts one failure. Both doors
 * bind through the product's McpCredentialBinder, so a tool sees the same
 * shape of credential either way.
 *
 * @api
 */
final class McpBearerDoorMiddleware
{
    public function __construct(
        private readonly McpOAuthServer $mcpOAuthServer,
        private readonly ApiKeyDoor $apiKeyDoor,
        private readonly McpCredentialBinder $credentialBinder,
        private readonly ConfigRepository $config,
        private readonly Container $container,
    ) {}

    /**
     * @param  Closure(Request): Response  $next
     */
    public function handle(Request $request, Closure $next): Response
    {
        $failureKey = 'mcp-auth-failures:'.ClientThrottleKey::fromRequest($request);
        $maxFailures = BoundedPositiveInt::require(
            $this->config->get('mcp-oauth.mcp_auth_failures_per_minute'),
            'mcp_auth_failures_per_minute',
            BoundedPositiveInt::RATE_LIMIT_PER_MINUTE_MAX,
        );

        if (RateLimiter::tooManyAttempts($failureKey, $maxFailures)) {
            return new JsonResponse(
                ['error' => 'temporarily_unavailable', 'error_description' => 'Too many failed attempts. Try again later.'],
                429,
                ['Retry-After' => RateLimiter::availableIn($failureKey)],
            );
        }

        try {
            $response = $this->admit($request, $next);
        } catch (HttpExceptionInterface $exception) {
            $this->countFailure($failureKey, $exception->getStatusCode());

            throw $exception;
        }

        $this->countFailure($failureKey, $response->getStatusCode());

        return $response;
    }

    /**
     * @param  Closure(Request): Response  $next
     */
    private function admit(Request $request, Closure $next): Response
    {
        $bearer = $request->bearerToken();

        if ($bearer === null || $bearer === '') {
            return new JsonResponse(['message' => 'Authentication required.'], 401);
        }

        if ($this->apiKeyDoor->isApiKeyShaped($bearer)) {
            $this->credentialBinder->bindApiKey($request, $this->apiKeyDoor->authenticate($request, $bearer));

            return $next($request);
        }

        if ($this->mcpOAuthServer->isEnabled() && ! $this->mcpOAuthServer->hasPassportKeys()) {
            return new JsonResponse(
                ['error' => 'temporarily_unavailable', 'error_description' => 'OAuth is unavailable because Passport keys are missing.'],
                503,
            );
        }

        if (! $this->mcpOAuthServer->isReady()) {
            $this->credentialBinder->bindApiKey($request, $this->apiKeyDoor->authenticate($request, $bearer));

            return $next($request);
        }

        // Resolved only now: Passport's ResourceServer needs the keys, which
        // may be missing, or unused, while OAuth is off.
        $grantOrRefusal = $this->container->make(AccessTokenAuthenticator::class)->authenticate($request);

        if ($grantOrRefusal instanceof AuthorizationDecision) {
            return self::refusal($grantOrRefusal);
        }

        $this->credentialBinder->bindGrant($request, $grantOrRefusal);

        return $next($request);
    }

    /**
     * The package renders RFC 6750 for a refused token. The status carries the
     * error code (403 `insufficient_scope`, 401 `invalid_token`), which
     * McpChallengeMiddleware writes with the resource metadata.
     */
    private static function refusal(AuthorizationDecision $decision): JsonResponse
    {
        $status = $decision->error === 'insufficient_scope' ? 403 : 401;
        $challenge = McpChallengeMiddleware::challenge([
            'error_description' => $decision->description,
            'scope' => $decision->scope,
        ]);

        return new JsonResponse(
            ['error' => $decision->error, 'error_description' => $decision->description],
            $status,
            ['WWW-Authenticate' => $challenge],
        );
    }

    private function countFailure(string $failureKey, int $status): void
    {
        if ($status === 401 || $status === 403) {
            RateLimiter::hit($failureKey);
        }
    }
}
