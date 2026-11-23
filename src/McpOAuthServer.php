<?php

declare(strict_types=1);

namespace Qiick\McpOAuth;

use DateInterval;
use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Laravel\Mcp\Server\Registrar;
use Laravel\Passport\Passport;
use Qiick\McpOAuth\Contracts\AdminSwitch;
use Qiick\McpOAuth\Internal\BoundedPositiveInt;
use Throwable;

/**
 * Whether OAuth for the product's MCP endpoint is on, ready, and which resource
 * tokens are issued for. Issuer and resource always come from APP_URL.
 *
 * @api
 */
final class McpOAuthServer
{
    public const string WIRE_SCOPE = Registrar::OAUTH_SCOPE;

    /*
     * pcov never covers a constant declaration, so mutation cannot run tests
     * against these two; McpOAuthServerTest pins both values instead.
     */

    /** @var list<string> */
    public const array SUPPORTED_GRANT_TYPES = ['authorization_code', 'refresh_token']; // @pest-mutate-ignore: RemoveArrayItem

    /** @var list<string> */
    public const array SUPPORTED_CODE_CHALLENGE_METHODS = ['S256']; // @pest-mutate-ignore: RemoveArrayItem

    public function __construct(
        private readonly ConfigRepository $config,
        private readonly AdminSwitch $adminSwitch,
        private readonly bool $skipUnixKeyModes = PHP_OS_FAMILY === 'Windows',
    ) {}

    public function isEnabled(): bool
    {
        if (! $this->config->get('mcp-oauth.enabled', false)) {
            return false;
        }

        // Design §4.2 / S11: a throwing admin switch counts as OFF, never 500.
        try {
            if (! $this->adminSwitch->enabled()) {
                return false;
            }
        } catch (Throwable) {
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
        if (! $this->isEnabled() || ! $this->hasPassportKeys()) {
            return false;
        }

        return preg_match('#^https?://[^/]#i', $this->issuer()) === 1;
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
        // RFC 8707: the resource is compared exactly, byte for byte; only a
        // trailing slash is ignored. Case folding would let a distinct path
        // (`/API/MCP` vs `/api/mcp`) stand for this resource.
        return is_string($resource)
            && rtrim($resource, '/') === $this->resourceIdentifier();
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
        return new DateInterval(sprintf(
            'PT%dM',
            BoundedPositiveInt::require(
                $this->config->get('mcp-oauth.access_token_ttl_minutes'),
                'access_token_ttl_minutes',
                BoundedPositiveInt::ACCESS_TOKEN_TTL_MINUTES_MAX,
            ),
        ));
    }

    public function refreshTokenLifetime(): DateInterval
    {
        return new DateInterval(sprintf(
            'P%dD',
            BoundedPositiveInt::require(
                $this->config->get('mcp-oauth.refresh_token_ttl_days'),
                'refresh_token_ttl_days',
                BoundedPositiveInt::REFRESH_TOKEN_TTL_DAYS_MAX,
            ),
        ));
    }

    private function mcpPath(): string
    {
        $path = $this->config->get('mcp-oauth.mcp_path', 'mcp');

        return trim(is_string($path) && $path !== '' ? $path : 'mcp', '/');
    }

    private function productMcpEnabled(): bool
    {
        $mcpEnabled = $this->config->get('mcp-oauth.mcp_enabled');

        if ($mcpEnabled instanceof \Closure) {
            return (bool) $mcpEnabled();
        }

        // An empty key names no config entry, so it reads the `false` default.
        if (is_string($mcpEnabled)) {
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

        if ($this->skipUnixKeyModes) {
            return true;
        }

        $permissions = decoct(fileperms($path) & 0777);

        return in_array($permissions, ['400', '440', '600', '640', '660'], true);
    }
}
