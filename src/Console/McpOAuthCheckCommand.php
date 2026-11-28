<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Console;

use Illuminate\Console\Command;
use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Qiick\McpOAuth\McpOAuthReadiness;
use Qiick\McpOAuth\McpOAuthRoutes;
use Qiick\McpOAuth\McpOAuthServer;
use Qiick\McpOAuth\Services\ClientMetadataRegistryService;

/**
 * `mcp-oauth:check` (design §5.4): reports whether OAuth is on, the issuer
 * and resource it advertises, where the Passport keys come from and whether
 * they are usable, any foreign `passport.*` route (design §3.3), and whether
 * the package alone serves its routes at the origin, the same check the
 * admin switch makes. It exits 1 beside a foreign Passport or laravel/mcp
 * OAuth route, when OAuth is on but not ready or not served, or when the
 * enabled Companion client has an unusable definition.
 *
 * The Passport key check comes from the same readiness probe products use.
 * The command supplements it with issuer, route and key source diagnostics.
 *
 * @internal
 */
final class McpOAuthCheckCommand extends Command
{
    protected $signature = 'mcp-oauth:check';

    protected $description = 'Report whether MCP OAuth is on and ready';

    public function handle(
        McpOAuthServer $mcpOAuthServer,
        McpOAuthReadiness $readiness,
        ConfigRepository $config,
        ClientMetadataRegistryService $clientMetadata,
    ): int {
        $checks = $readiness->checks();
        $isEnabled = $checks !== [];
        // Operators can inspect the key source and status before enabling OAuth.
        $hasUsableKeys = isset($checks['passport_keys'])
            ? $checks['passport_keys'] === 'ok'
            : $mcpOAuthServer->hasPassportKeys();
        // McpOAuthServer::hasPassportKeys() reads the env pair first, then the key files.
        $hasEnvKeys = self::isFilled($config->get('passport.private_key')) || self::isFilled($config->get('passport.public_key'));
        $foreignRouteNames = McpOAuthRoutes::foreignPassportRouteNames();
        $laravelMcpRouteNames = McpOAuthRoutes::laravelMcpOAuthRouteNames();
        $servingProblems = McpOAuthRoutes::servingProblems();

        $this->line('OAuth: '.($isEnabled ? 'on' : 'off'));
        $this->line('Issuer: '.$mcpOAuthServer->issuer());
        $this->line('Resource: '.$mcpOAuthServer->resourceIdentifier());
        $this->line('Passport keys: '.($hasEnvKeys ? 'env' : 'file').', '.($hasUsableKeys ? 'usable' : 'missing or unusable'));
        $this->line('Foreign Passport routes: '.($foreignRouteNames === [] ? 'none' : implode(', ', $foreignRouteNames)));
        $this->line('laravel/mcp OAuth routes: '.($laravelMcpRouteNames === [] ? 'none' : implode(', ', $laravelMcpRouteNames)));
        $this->line('Package routes: '.($servingProblems === [] ? 'served at the origin' : implode('; ', $servingProblems)));

        $companionProblems = $clientMetadata->companionConfigurationProblems();

        foreach ($companionProblems as $problem) {
            $this->warn($problem);
        }

        $isHealthy = $foreignRouteNames === [] && $laravelMcpRouteNames === [] && $companionProblems === []
            && (! $isEnabled || ($hasUsableKeys && $mcpOAuthServer->hasAbsoluteIssuer() && $servingProblems === []));

        return $isHealthy ? self::SUCCESS : self::FAILURE;
    }

    private static function isFilled(mixed $value): bool
    {
        return is_string($value) && $value !== '';
    }
}
