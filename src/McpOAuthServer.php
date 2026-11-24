<?php

declare(strict_types=1);

namespace Qiick\McpOAuth;

use DateInterval;
use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Laravel\Mcp\Server\Registrar;
use Laravel\Passport\Passport;
use Qiick\McpOAuth\Contracts\AdminSwitch;
use Qiick\McpOAuth\Exceptions\InvalidMcpOAuthConfigException;
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

    /**
     * RFC 8707 resource check. The path is compared byte for byte; scheme
     * and host are case-insensitive (RFC 3986 §6.2.2.1), and the MCP spec
     * says implementations SHOULD accept them in upper case. One trailing
     * slash names the same resource (RFC 9728 §3.1); more does not.
     */
    public function acceptsResource(mixed $resource): bool
    {
        if (! is_string($resource)) {
            return false;
        }

        $withoutTrailingSlash = str_ends_with($resource, '/') ? substr($resource, 0, -1) : $resource;

        return $this->lowercaseSchemeAndAuthority($withoutTrailingSlash)
            === $this->lowercaseSchemeAndAuthority($this->resourceIdentifier());
    }

    public function protectedResourceMetadataUrl(): string
    {
        return $this->issuer().'/.well-known/oauth-protected-resource/'.$this->mcpPath();
    }

    /**
     * The MCP authorization spec revision this server implements (M8), a
     * `YYYY-MM-DD` date. Fails closed on anything else rather than stamp a
     * client row with a revision nobody can compare.
     *
     * @throws InvalidMcpOAuthConfigException
     */
    public function specRevision(): string
    {
        $specRevision = $this->config->get('mcp-oauth.spec_revision');

        if (! is_string($specRevision) || preg_match('/^\d{4}-\d{2}-\d{2}\z/', $specRevision) !== 1) {
            throw InvalidMcpOAuthConfigException::invalidSpecRevision();
        }

        return $specRevision;
    }

    /**
     * RFC 7009 endpoint, or null when `revocation_enabled` is not exactly
     * true: then McpOAuthRoutes registers no `oauth/revoke` and the metadata
     * does not advertise it (M2).
     */
    public function revocationEndpointUrl(): ?string
    {
        if ($this->config->get('mcp-oauth.revocation_enabled', true) !== true) {
            return null;
        }

        return $this->issuer().'/oauth/revoke';
    }

    /**
     * Whether `client_id` may be a Client ID Metadata Document URL (S2).
     *
     * ponytail: always false until the fetcher lands on qiick/laravel-outbound;
     * then it reads `mcp-oauth.cimd.enabled` and authorizationServerMetadata()
     * adds `client_id_metadata_document_supported` when it is true.
     * Advertising it with no handler would make clients send URLs the server
     * cannot resolve (M2).
     */
    public function supportsClientIdMetadataDocuments(): bool
    {
        return false;
    }

    /**
     * RFC 8414 authorization server metadata, served at the root and nested
     * well-known paths. Every URL comes from the issuer (APP_URL), never the
     * request Host, and only what is switched on is advertised (M2).
     *
     * @return array<string, mixed>
     */
    public function authorizationServerMetadata(): array
    {
        $issuer = $this->issuer();
        $revocationEndpointUrl = $this->revocationEndpointUrl();
        // Passport clients authenticate with a secret in Basic or the body; DCR clients with none.
        $clientAuthenticationMethods = ['none', 'client_secret_basic', 'client_secret_post'];

        $metadata = [
            'issuer' => $issuer,
            'authorization_endpoint' => $issuer.'/oauth/authorize',
            'token_endpoint' => $issuer.'/oauth/token',
            'registration_endpoint' => $issuer.'/oauth/register',
            'revocation_endpoint' => $revocationEndpointUrl,
            'scopes_supported' => [self::WIRE_SCOPE],
            'response_types_supported' => ['code'],
            'grant_types_supported' => self::SUPPORTED_GRANT_TYPES,
            'code_challenge_methods_supported' => self::SUPPORTED_CODE_CHALLENGE_METHODS,
            'token_endpoint_auth_methods_supported' => $clientAuthenticationMethods,
            'revocation_endpoint_auth_methods_supported' => $clientAuthenticationMethods,
            'authorization_response_iss_parameter_supported' => true,
        ];

        if ($revocationEndpointUrl === null) {
            unset($metadata['revocation_endpoint'], $metadata['revocation_endpoint_auth_methods_supported']);
        }

        return $metadata;
    }

    /**
     * RFC 9728 metadata of the MCP endpoint, one document for the root and
     * the nested well-known path. Bearer tokens go in the Authorization
     * header only.
     *
     * @return array<string, mixed>
     */
    public function protectedResourceMetadata(): array
    {
        return [
            'resource' => $this->resourceIdentifier(),
            'authorization_servers' => [$this->issuer()],
            'scopes_supported' => [self::WIRE_SCOPE],
            'bearer_methods_supported' => ['header'],
        ];
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
        $trimmedPath = is_string($path) ? trim($path, '/') : '';

        // An empty or slash-only path would make the resource the bare origin.
        return $trimmedPath !== '' ? $trimmedPath : 'mcp';
    }

    /**
     * Everything before the path: an absolute URI's scheme and authority.
     * Userinfo is lowered too, which is harmless: the resource identifier
     * has none, so a candidate carrying one never matches.
     */
    private function lowercaseSchemeAndAuthority(string $uri): string
    {
        return preg_replace_callback(
            '#^[^/]*//[^/?\#]*#',
            static fn (array $schemeAndAuthority): string => strtolower($schemeAndAuthority[0]),
            $uri,
        ) ?? $uri;
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
