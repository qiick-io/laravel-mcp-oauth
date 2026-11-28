<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Services;

use DateTimeInterface;
use Illuminate\Contracts\Cache\Repository as CacheRepository;
use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Container\Container;
use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Support\Str;
use InvalidArgumentException;
use Laravel\Passport\Client;
use Laravel\Passport\ClientRepository;
use Laravel\Passport\Passport;
use Qiick\McpOAuth\Contracts\ClientMetadataDocumentFetcherContract;
use Qiick\McpOAuth\Data\ClientMetadataDocumentData;
use Qiick\McpOAuth\Enums\ClientMetadataFetchStatusEnum;
use Qiick\McpOAuth\Exceptions\ClientMetadataUnavailableException;
use Qiick\McpOAuth\Internal\BoundedPositiveInt;
use Qiick\McpOAuth\McpOAuthServer;
use Qiick\McpOAuth\Models\OAuthClientMetadata;
use Qiick\McpOAuth\RedirectUriGuard;

/**
 * Resolves a public CIMD identifier to its internal Passport UUID. The client
 * and its validated metadata are written together on Passport's connection.
 *
 * @internal
 */
final class ClientMetadataRegistryService
{
    public function __construct(
        private readonly ConfigRepository $config,
        private readonly Container $container,
        private readonly McpOAuthServer $server,
        private readonly RedirectUriGuard $redirectUriGuard,
        private readonly ClientRepository $clients,
        private readonly CacheRepository $cache,
    ) {}

    /**
     * A CIMD client's internal Passport UUID is never a wire identifier. UUIDs
     * issued by DCR or a product retain their existing semantics.
     */
    public function isRegisteredWireUuid(string $clientId): bool
    {
        return OAuthClientMetadata::query()->where('client_id', $clientId)->whereNull('metadata_document_url')->exists();
    }

    /**
     * @throws ClientMetadataUnavailableException when discovery temporarily fails
     */
    public function resolve(string $url, bool $canRegister = false): ?Client
    {
        if (! $this->server->supportsClientIdMetadataDocuments() || ! $this->isIdentifierAllowed($url)) {
            return null;
        }

        $metadata = $this->findMetadata($url);
        $client = $this->findActiveClient($metadata);

        if (($metadata !== null && $client === null) || ($metadata === null && ! $canRegister)) {
            return null;
        }

        if ($this->isFresh($metadata)) {
            return $client !== null && $this->hasAllowedRedirects(self::stringList($client->getAttribute('redirect_uris'))) ? $client : null;
        }

        if ($metadata === null && $this->hasReachedRegistrationCapacity()) {
            throw new ClientMetadataUnavailableException;
        }

        $retryKey = 'mcp-oauth:cimd:'.hash('sha256', $url);
        $minimumSeconds = $this->cacheMinimumSeconds();

        // Reserve the fetch on the application's shared cache. A negative
        // entry holds only a status, even for URLs that never had a client row.
        if (! $this->cache->add($retryKey, ClientMetadataFetchStatusEnum::Unavailable->value, max($minimumSeconds, BoundedPositiveInt::CIMD_TIMEOUT_SECONDS_MAX + 1))) {
            if ($this->cache->get($retryKey) === ClientMetadataFetchStatusEnum::Invalid->value) {
                return null;
            }

            throw new ClientMetadataUnavailableException;
        }

        $etag = $metadata?->getAttribute('metadata_document_etag');
        $response = $this->container->make(ClientMetadataDocumentFetcherContract::class)->fetch($url, is_string($etag) ? $etag : null);

        try {
            /** @var Client|null $resolved Laravel 12 types transaction() as mixed */
            $resolved = Passport::client()->getConnection()->transaction(
                fn (): ?Client => $this->applyFetch($url, $metadata, $response),
                attempts: 3,
            );
        } catch (UniqueConstraintViolationException $exception) {
            // The metadata URL's unique digest serialises concurrent first registrations.
            $winner = $this->findMetadata($url);

            if ($metadata !== null || $winner === null) {
                throw $exception;
            }

            $resolved = $this->isFresh($winner) ? $this->findActiveClient($winner) : null;
        }

        if ($response->status === ClientMetadataFetchStatusEnum::Unavailable) {
            $this->cache->put($retryKey, ClientMetadataFetchStatusEnum::Unavailable->value, $minimumSeconds);

            throw new ClientMetadataUnavailableException;
        }

        if ($resolved === null || ! $this->hasAllowedRedirects(self::stringList($resolved->getAttribute('redirect_uris')))) {
            $this->cache->put($retryKey, ClientMetadataFetchStatusEnum::Invalid->value, $minimumSeconds);

            return null;
        }

        $this->cache->forget($retryKey);

        return $resolved;
    }

    /** A client can revoke its own tokens even during a metadata outage. */
    public function findForRevocation(string $url): ?Client
    {
        if (! $this->server->supportsClientIdMetadataDocuments() || ! $this->isIdentifierAllowed($url)) {
            return null;
        }

        return $this->findActiveClient($this->findMetadata($url));
    }

    private function isIdentifierAllowed(string $url): bool
    {
        if (strlen($url) > 2048 || trim($url) !== $url || str_contains($url, '?') || $url === $this->server->resourceIdentifier()) {
            return false;
        }

        try {
            $parsed = $this->redirectUriGuard->parseCanonical($url);
        } catch (InvalidArgumentException) {
            return false;
        }

        foreach (explode('/', $parsed->path) as $segment) {
            if (in_array(rawurldecode($segment), ['.', '..'], true)) {
                return false;
            }
        }

        return $parsed->scheme === 'https'
            && $parsed->path !== ''
            && $parsed->path !== '/'
            && $parsed->normalizedHost !== null
            && ! $this->redirectUriGuard->isHostBlocked($parsed->normalizedHost);
    }

    private function findMetadata(string $url, bool $shouldLock = false): ?OAuthClientMetadata
    {
        $query = OAuthClientMetadata::query()->where('metadata_document_url_sha256', hash('sha256', $url));

        if ($shouldLock) {
            $query->lockForUpdate();
        }

        $metadata = $query->first();

        return $metadata?->getAttribute('metadata_document_url') === $url ? $metadata : null;
    }

    private function findActiveClient(?OAuthClientMetadata $metadata): ?Client
    {
        if ($metadata === null || $metadata->getAttribute('revoked_at') !== null) {
            return null;
        }

        return Passport::client()->newQuery()->whereKey($metadata->getAttribute('client_id'))->where('revoked', false)->first();
    }

    private function isFresh(?OAuthClientMetadata $metadata): bool
    {
        $expiresAt = $metadata?->getAttribute('metadata_document_expires_at');

        return $metadata !== null
            && $metadata->getAttribute('metadata_document_status') === 'valid'
            && $expiresAt instanceof DateTimeInterface
            && $expiresAt > now();
    }

    private function hasReachedRegistrationCapacity(): bool
    {
        $capacity = BoundedPositiveInt::require($this->config->get('mcp-oauth.registrations_global_cap'), 'registrations_global_cap', BoundedPositiveInt::REGISTRATIONS_GLOBAL_CAP_MAX);

        return Passport::client()->newQuery()->where('revoked', false)->count() >= $capacity;
    }

    /** @param list<string> $redirectUris */
    private function hasAllowedRedirects(array $redirectUris): bool
    {
        foreach ($redirectUris as $redirectUri) {
            if (! $this->isAllowedRedirectUri($redirectUri)) {
                return false;
            }
        }

        return $redirectUris !== [];
    }

    /** Applies the MCP redirect domain policy to the document's callbacks. */
    private function isAllowedRedirectUri(string $redirectUri): bool
    {
        if (strlen($redirectUri) > 1024 || ! $this->redirectUriGuard->isAcceptableForRegistration($redirectUri)) {
            return false;
        }

        $parsed = $this->redirectUriGuard->parseCanonical($redirectUri);

        if ($parsed->normalizedHost !== null && $this->redirectUriGuard->isHostBlocked($parsed->normalizedHost)) {
            return false;
        }

        if ($parsed->scheme !== 'http' && $parsed->scheme !== 'https') {
            return true;
        }

        $allowedDomains = self::stringList($this->config->get('mcp.redirect_domains', ['*']));

        foreach ($allowedDomains as $domain) {
            if ($domain === '*' || str_starts_with($redirectUri, rtrim($domain, '/').'/')) {
                return true;
            }

            if ($parsed->scheme === 'http' && $this->redirectUriGuard->isLoopbackRedirectUri($redirectUri)
                && in_array(rtrim(Str::after($domain, '://'), '/'), ['localhost', '127.0.0.1', '[::1]'], true)) {
                return true;
            }
        }

        return false;
    }

    private function applyFetch(string $url, ?OAuthClientMetadata $beforeFetch, ClientMetadataDocumentData $response): ?Client
    {
        $metadata = $this->findMetadata($url, shouldLock: true);
        $client = $this->findActiveClient($metadata);

        // Never overwrite a registration or cache entry updated during the HTTP request.
        if ($metadata?->getRawOriginal() !== $beforeFetch?->getRawOriginal()) {
            return $this->isFresh($metadata) ? $client : null;
        }

        if ($metadata !== null && $client === null) {
            return null;
        }

        if ($response->status === ClientMetadataFetchStatusEnum::Unavailable) {
            $metadata?->update(['metadata_document_status' => 'fetch_failed', 'metadata_document_error' => 'unavailable']);

            return null;
        }

        if ($response->status === ClientMetadataFetchStatusEnum::NotModified && $metadata !== null
            && $metadata->getAttribute('metadata_document_etag') !== null && $metadata->getAttribute('metadata_document') !== null) {
            $this->updateCache($metadata, $response);

            return $client;
        }

        $document = $response->document;
        $validated = $response->status === ClientMetadataFetchStatusEnum::Fetched ? $this->validateDocument($url, $document) : null;

        if ($validated === null) {
            if ($client !== null) {
                $this->revokeIssuedCredentials($client);
            }

            $metadata?->update([
                'metadata_document_status' => 'invalid',
                'metadata_document_error' => 'invalid_document',
                'metadata_document_etag' => null,
                'metadata_document_expires_at' => null,
            ]);

            return null;
        }

        ['client_name' => $name, 'redirect_uris' => $redirectUris, 'grant_types' => $grantTypes] = $validated;

        if ($client !== null && ($client->getAttribute('redirect_uris') !== $redirectUris || $client->getAttribute('grant_types') !== $grantTypes)) {
            $this->revokeIssuedCredentials($client);
        }

        $client ??= $this->clients->createAuthorizationCodeGrantClient($name, $redirectUris, confidential: false);
        $client->forceFill(['name' => $name, 'redirect_uris' => $redirectUris, 'grant_types' => $grantTypes])->save();

        $metadata ??= new OAuthClientMetadata([
            'client_id' => $client->getKey(),
            'registration_source' => 'cimd',
            'spec_revision' => $this->server->specRevision(),
            'token_endpoint_auth_method' => 'none',
            'client_id_issued_at' => now(),
            'metadata_document_url' => $url,
            'metadata_document_url_sha256' => hash('sha256', $url),
        ]);
        $this->updateCache($metadata, $response, ['client_id' => $url, ...$validated]);

        return $client;
    }

    /** A terminal refusal or changed callback/grant policy retires credentials issued under the previous policy. */
    private function revokeIssuedCredentials(Client $client): void
    {
        Passport::refreshToken()->newQuery()->whereIn('access_token_id', $client->tokens()->select('id'))->update(['revoked' => true]);
        $client->tokens()->update(['revoked' => true]);
        $client->authCodes()->update(['revoked' => true]);
    }

    private function cacheMinimumSeconds(): int
    {
        return BoundedPositiveInt::require($this->config->get('mcp-oauth.cimd.cache_min_seconds'), 'cimd.cache_min_seconds', BoundedPositiveInt::CIMD_CACHE_SECONDS_MAX);
    }

    /**
     * @param  array<string, mixed>  $document  only the validated, supported metadata is persisted
     */
    private function updateCache(OAuthClientMetadata $metadata, ClientMetadataDocumentData $response, ?array $document = null): void
    {
        $minimumSeconds = $this->cacheMinimumSeconds();
        $maximumSeconds = BoundedPositiveInt::require($this->config->get('mcp-oauth.cimd.cache_max_seconds'), 'cimd.cache_max_seconds', BoundedPositiveInt::CIMD_CACHE_SECONDS_MAX);
        $freshnessSeconds = $response->maxAgeSeconds;
        $previousEtag = null;

        if ($response->status === ClientMetadataFetchStatusEnum::NotModified) {
            $previousEtag = $metadata->getAttribute('metadata_document_etag');
            $previousFetchedAt = $metadata->getAttribute('metadata_document_fetched_at');
            $previousExpiresAt = $metadata->getAttribute('metadata_document_expires_at');

            if ($freshnessSeconds === null && $previousFetchedAt instanceof DateTimeInterface && $previousExpiresAt instanceof DateTimeInterface) {
                $freshnessSeconds = $previousExpiresAt->getTimestamp() - $previousFetchedAt->getTimestamp();
            }
        }

        // Keep operational registration fields for the minimum interval. A
        // no-store response leaves neither a document body nor a validator.
        $freshnessSeconds = $response->shouldCache ? min($maximumSeconds, max($minimumSeconds, $freshnessSeconds ?? 0)) : $minimumSeconds;
        $fetchedAt = now();

        $metadata->fill([
            'metadata_document' => $response->shouldCache ? ($document ?? $metadata->getAttribute('metadata_document')) : null,
            'metadata_document_sha256' => $response->shouldCache && $document !== null
                ? hash('sha256', json_encode($document, JSON_THROW_ON_ERROR))
                : ($response->shouldCache ? $metadata->getAttribute('metadata_document_sha256') : null),
            'metadata_document_etag' => $response->shouldCache ? ($response->etag ?? $previousEtag) : null,
            'metadata_document_fetched_at' => $fetchedAt,
            'metadata_document_expires_at' => $fetchedAt->copy()->addSeconds($freshnessSeconds),
            'metadata_document_status' => 'valid',
            'metadata_document_error' => null,
        ])->save();
    }

    /**
     * @param  array<string, mixed>  $document
     * @return array{client_name: string, redirect_uris: non-empty-list<string>, grant_types: list<string>}|null
     */
    private function validateDocument(string $url, array $document): ?array
    {
        $authenticationMethods = self::stringList(array_key_exists('token_endpoint_auth_methods_supported', $document) ? $document['token_endpoint_auth_methods_supported'] : ['none']);
        $authenticationMethod = array_key_exists('token_endpoint_auth_method', $document) ? $document['token_endpoint_auth_method'] : 'none';
        $grantTypes = array_values(array_intersect(McpOAuthServer::supportedGrantTypes(), self::stringList($document['grant_types'] ?? ['authorization_code'])));

        if (($document['client_id'] ?? null) !== $url
            || array_key_exists('client_secret', $document) || array_key_exists('client_secret_expires_at', $document)
            || $authenticationMethod !== 'none' || $authenticationMethods !== ['none']
            || ! in_array('authorization_code', $grantTypes, true)
            || ! in_array('code', self::stringList($document['response_types'] ?? ['code']), true)) {
            return null;
        }

        $redirectUris = self::stringList($document['redirect_uris'] ?? null);

        if ($redirectUris === [] || count($redirectUris) > 10 || ! $this->hasAllowedRedirects($redirectUris)) {
            return null;
        }

        $name = $document['client_name'] ?? null;

        if (! is_string($name) || Str::length($name) > 255 || preg_match('/\A[\p{L}\p{N}\p{P}\p{S}\p{M} ]+\z/u', $name) !== 1 || trim($name) === '') {
            $name = $this->redirectUriGuard->displayHostOf($url);
        }

        return ['client_name' => $name, 'redirect_uris' => $redirectUris, 'grant_types' => $grantTypes];
    }

    /** @return list<string> */
    private static function stringList(mixed $value): array
    {
        if (! is_array($value) || ! array_is_list($value)) {
            return [];
        }

        foreach ($value as $entry) {
            if (! is_string($entry) || $entry === '') {
                return [];
            }
        }

        return $value;
    }
}
