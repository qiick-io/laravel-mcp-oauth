<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Qiick\McpOAuth\Events\McpPassportKeysMissing;
use Qiick\McpOAuth\McpOAuthServer;
use Symfony\Component\HttpFoundation\Response;

/**
 * Per-request gate for package OAuth routes (design Resolved #3 / S1–S3 / S7).
 * Off → 404. On without usable Passport keys → 503 temporarily_unavailable
 * and {@see McpPassportKeysMissing}.
 */
final class EnsureMcpOAuthEnabledMiddleware
{
    public function __construct(
        private readonly McpOAuthServer $mcpOAuthServer,
    ) {}

    /**
     * @param  Closure(Request): Response  $next
     */
    public function handle(Request $request, Closure $next): Response
    {
        if (! $this->mcpOAuthServer->isEnabled()) {
            abort(404);
        }

        if (! $this->mcpOAuthServer->hasPassportKeys()) {
            event(new McpPassportKeysMissing(
                endpoint: $request->path(),
                reason: 'unreadable',
            ));

            return response()->json([
                'error' => 'temporarily_unavailable', // @pest-mutate-ignore: RemoveArrayItem — both keys are the RFC 6750 wire shape
                'error_description' => 'OAuth is unavailable because Passport keys are missing.',
            ], 503);
        }

        return $next($request);
    }
}
