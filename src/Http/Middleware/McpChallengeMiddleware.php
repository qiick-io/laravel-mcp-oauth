<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Qiick\McpOAuth\McpOAuthServer;
use Symfony\Component\HttpFoundation\Response;

/**
 * The RFC 6750 challenge of `/mcp` (design §5.3). It replaces laravel/mcp's
 * AddWwwAuthenticateHeader (`->withoutMiddleware(AddWwwAuthenticateHeader::class)`),
 * which overwrites the error code and builds its pointer from the request host.
 *
 * - **OAuth off:** a 401 carries `Bearer realm="mcp", error="invalid_token"`,
 *   exactly as before the package (S5).
 * - **OAuth on:** every 401 and 403 points at the protected resource metadata,
 *   built from APP_URL. A request without credentials gets no error code and
 *   the scope to ask for (`mcp:use`); a refused credential keeps
 *   `invalid_token` (or the door's code and description); a 403 keeps
 *   `insufficient_scope` with its scope.
 *
 * @api
 */
final class McpChallengeMiddleware
{
    public function __construct(
        private readonly McpOAuthServer $mcpOAuthServer,
    ) {}

    /**
     * @param  Closure(Request): Response  $next
     */
    public function handle(Request $request, Closure $next): Response
    {
        $response = $next($request);
        $status = $response->getStatusCode();

        if ($status !== 401 && $status !== 403) {
            return $response;
        }

        if (! $this->mcpOAuthServer->isEnabled()) {
            if ($status === 401) {
                $response->headers->set('WWW-Authenticate', self::challenge(['error' => 'invalid_token']));
            }

            return $response;
        }

        $parameters = self::parametersOf($response->headers->get('WWW-Authenticate'));

        // An empty `Bearer` is no credential, as for the door.
        if (! isset($parameters['error']) && (string) $request->bearerToken() !== '') {
            $parameters['error'] = $status === 403 ? 'insufficient_scope' : 'invalid_token';
        }

        if (! isset($parameters['error'])) {
            $parameters['scope'] = McpOAuthServer::WIRE_SCOPE;
        }

        $parameters['resource_metadata'] = $this->mcpOAuthServer->protectedResourceMetadataUrl();
        $response->headers->set('WWW-Authenticate', self::challenge($parameters));

        return $response;
    }

    /**
     * `Bearer realm="mcp"` and the parameters given, in RFC 6750 order; a
     * quote or backslash in a value becomes an apostrophe (§3: not allowed).
     *
     * @param  array<string, string|null>  $parameters
     */
    public static function challenge(array $parameters): string
    {
        $challenge = 'Bearer realm="mcp"';

        foreach (['error', 'error_description', 'scope', 'resource_metadata'] as $name) {
            $value = $parameters[$name] ?? null;

            if ($value !== null) {
                $challenge .= ', '.$name.'="'.str_replace(['"', '\\'], "'", $value).'"';
            }
        }

        return $challenge;
    }

    /**
     * The parameters of a Bearer challenge the door already set.
     *
     * @return array<string, string>
     */
    private static function parametersOf(?string $challenge): array
    {
        if ($challenge === null || ! str_starts_with($challenge, 'Bearer ')) {
            return [];
        }

        preg_match_all('/(\w+)="([^"]*)"/', $challenge, $matches, PREG_SET_ORDER);
        $parameters = [];

        foreach ($matches as [, $name, $value]) {
            $parameters[$name] = $value;
        }

        unset($parameters['realm']);

        return $parameters;
    }
}
