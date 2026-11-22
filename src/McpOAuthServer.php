<?php

declare(strict_types=1);

namespace Qiick\McpOAuth;

use DateInterval;
use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Laravel\Mcp\Server\Registrar;
use Laravel\Passport\Passport;
use Qiick\McpOAuth\Contracts\AdminSwitch;

/**
 * Whether OAuth for the product's MCP endpoint is on, ready, and which resource
 * tokens are issued for. Issuer and resource always come from APP_URL.
 *
 * @api
 */
final class McpOAuthServer
{
    public const string WIRE_SCOPE = Registrar::OAUTH_SCOPE;

    /** @var list<string> */
    public const array SUPPORTED_GRANT_TYPES = ['authorization_code', 'refresh_token'];

    /** @var list<string> */
    public const array SUPPORTED_CODE_CHALLENGE_METHODS = ['S256'];

    public function __construct(
        private readonly ConfigRepository $config,
        private readonly AdminSwitch $adminSwitch,
    ) {}

    public function isEnabled(): bool
    {
        if (! (bool) $this->config->get('mcp-oauth.enabled', false)) {
            return false;
        }

        if (! $this->adminSwitch->enabled()) {
            return false;
        }

        return $this->productMcpEnabled();
    }

    public function hasPassportKeys(): bool
    {
        $privateKey = $this->config->get('passport.private_key');
        $publicKey = $this->config->get('passport.public_key');
        $hasPrivateEnv = is_string($privateKey) && $privateKey !== '';
        $hasPublicEnv = is_string($publicKey) && $publicKey !== '';

        if ($hasPrivateEnv || $hasPublicEnv) {
            return $hasPrivateEnv && $hasPublicEnv;
        }

        $privatePath = Passport::keyPath('oauth-private.key');
        $publicPath = Passport::keyPath('oauth-public.key');

        return $this->keyFileIsUsable($privatePath) && $this->keyFileIsUsable($publicPath);
    }

    public function isReady(): bool
    {
        return $this->isEnabled() && $this->hasPassportKeys();
    }

    public function issuer(): string
    {
        $appUrl = $this->config->get('app.url');

        return rtrim(is_string($appUrl) ? $appUrl : '', '/');
    }

    public function resourceIdentifier(): string
    {
        return $this->issuer().'/'.$this->mcpPath();
    }

    public function acceptsResource(mixed $resource): bool
    {
        return is_string($resource) && rtrim($resource, '/') === $this->resourceIdentifier();
    }

    public function protectedResourceMetadataUrl(): string
    {
        return $this->issuer().'/.well-known/oauth-protected-resource/'.$this->mcpPath();
    }

    /**
     * @return array<string, string>
     */
    public function scopeDescriptions(): array
    {
        return [
            self::WIRE_SCOPE => 'Use the MCP server with the access the user grants',
        ];
    }

    public function accessTokenLifetime(): DateInterval
    {
        return new DateInterval(sprintf('PT%dM', $this->positiveConfigInt('mcp-oauth.access_token_ttl_minutes', 60)));
    }

    public function refreshTokenLifetime(): DateInterval
    {
        return new DateInterval(sprintf('P%dD', $this->positiveConfigInt('mcp-oauth.refresh_token_ttl_days', 30)));
    }

    private function mcpPath(): string
    {
        $path = $this->config->get('mcp-oauth.mcp_path', 'mcp');

        return ltrim(is_string($path) && $path !== '' ? $path : 'mcp', '/');
    }

    private function positiveConfigInt(string $key, int $default): int
    {
        $value = $this->config->get($key, $default);

        return max(1, is_int($value) ? $value : $default);
    }

    private function productMcpEnabled(): bool
    {
        $mcpEnabled = $this->config->get('mcp-oauth.mcp_enabled');

        if ($mcpEnabled instanceof \Closure) {
            return (bool) $mcpEnabled();
        }

        if (is_string($mcpEnabled) && $mcpEnabled !== '') {
            return (bool) $this->config->get($mcpEnabled, false);
        }

        if (is_bool($mcpEnabled)) {
            return $mcpEnabled;
        }

        // Null / unset: gate 3 fails closed (OAuth cannot be on).
        return false;
    }

    private function keyFileIsUsable(string $path): bool
    {
        if (! is_readable($path)) {
            return false;
        }

        if (PHP_OS_FAMILY === 'Windows') {
            return true;
        }

        $permissions = decoct(fileperms($path) & 0777);

        return in_array($permissions, ['400', '440', '600', '640', '660'], true);
    }
}
