<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Console;

use Illuminate\Console\Command;
use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Qiick\McpOAuth\McpOAuthRoutes;
use Qiick\McpOAuth\McpOAuthServer;

/**
 * `mcp-oauth:check` (design §5.4): reports whether OAuth is on, the issuer
 * and resource it advertises, where the Passport keys come from and whether
 * they are usable, and any foreign `passport.*` route (design §3.3). It
 * exits 1 when OAuth is on but not ready, or beside a foreign Passport route.
 *
 * @api
 */
final class McpOAuthCheckCommand extends Command
{
    protected $signature = 'mcp-oauth:check';

    protected $description = 'Report whether MCP OAuth is on and ready';

    public function handle(McpOAuthServer $mcpOAuthServer, ConfigRepository $config): int
    {
        $isEnabled = $mcpOAuthServer->isEnabled();
        // McpOAuthServer::hasPassportKeys() reads the env pair first, then the key files.
        $hasEnvKeys = self::isFilled($config->get('passport.private_key')) || self::isFilled($config->get('passport.public_key'));
        $foreignRouteNames = McpOAuthRoutes::foreignPassportRouteNames();

        $this->line('OAuth: '.($isEnabled ? 'on' : 'off'));
        $this->line('Issuer: '.$mcpOAuthServer->issuer());
        $this->line('Resource: '.$mcpOAuthServer->resourceIdentifier());
        $this->line('Passport keys: '.($hasEnvKeys ? 'env' : 'file').', '.($mcpOAuthServer->hasPassportKeys() ? 'usable' : 'missing or unusable'));
        $this->line('Foreign Passport routes: '.($foreignRouteNames === [] ? 'none' : implode(', ', $foreignRouteNames)));

        $isHealthy = $foreignRouteNames === [] && (! $isEnabled || $mcpOAuthServer->isReady());

        return $isHealthy ? self::SUCCESS : self::FAILURE;
    }

    private static function isFilled(mixed $value): bool
    {
        return is_string($value) && $value !== '';
    }
}
