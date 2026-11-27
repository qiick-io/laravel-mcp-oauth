<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Internal;

use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Http\Client\Response;
use JsonException;
use Qiick\McpOAuth\Contracts\ClientMetadataDocumentFetcherContract;
use Qiick\McpOAuth\Data\ClientMetadataDocumentData;
use Qiick\McpOAuth\Enums\ClientMetadataFetchStatusEnum;
use Qiick\Outbound\Http\HttpRequestOptions;
use Qiick\Outbound\Http\OutboundHttpException;
use Qiick\Outbound\Http\OutboundHttpStackData;
use Qiick\Outbound\Http\OutboundRequest;
use Qiick\Outbound\Ssrf\UnsafeUrl;
use stdClass;

/**
 * Fetches and decodes CIMD over HTTPS with a private Outbound stack. Product
 * webhook settings cannot enable redirects, proxies or private hosts here.
 *
 * @internal
 */
final class OutboundClientMetadataDocumentFetcher implements ClientMetadataDocumentFetcherContract
{
    private readonly OutboundHttpStackData $stack;

    public function __construct(private readonly ConfigRepository $config, ?OutboundHttpStackData $stack = null)
    {
        $this->stack = $stack ?? OutboundHttpStackData::make(new ClientMetadataHostResolver);
    }

    public function fetch(string $metadataDocumentUrl, ?string $etag = null): ClientMetadataDocumentData
    {
        $timeoutSeconds = BoundedPositiveInt::require(
            $this->config->get('mcp-oauth.cimd.timeout_seconds'),
            'cimd.timeout_seconds',
            BoundedPositiveInt::CIMD_TIMEOUT_SECONDS_MAX,
        );
        $maxDocumentBytes = BoundedPositiveInt::require(
            $this->config->get('mcp-oauth.cimd.max_document_bytes'),
            'cimd.max_document_bytes',
            BoundedPositiveInt::CIMD_MAX_DOCUMENT_BYTES_MAX,
        );
        $headers = ['Accept' => 'application/json'];
        $etag = self::safeEtag($etag ?? '');

        if ($etag !== null) {
            $headers['If-None-Match'] = $etag;
        }

        try {
            $response = $this->stack->client->send('GET', $metadataDocumentUrl, static function (OutboundRequest $request) use ($headers): void {
                $request->withHeaders($headers);
            }, new HttpRequestOptions(
                timeoutSeconds: $timeoutSeconds,
                connectTimeoutSeconds: min($timeoutSeconds, 3),
                maxResponseBytes: $maxDocumentBytes,
            ));
        } catch (UnsafeUrl) {
            return new ClientMetadataDocumentData(ClientMetadataFetchStatusEnum::Invalid);
        } catch (OutboundHttpException $exception) {
            return new ClientMetadataDocumentData($exception->transportErrorKind() === null
                ? ClientMetadataFetchStatusEnum::Invalid
                : ClientMetadataFetchStatusEnum::Unavailable);
        }

        $status = $response->status();

        if ($status === 304 && $etag !== null) {
            return self::cacheResult($response, ClientMetadataFetchStatusEnum::NotModified);
        }

        if ($status === 429 || $response->serverError()) {
            return new ClientMetadataDocumentData(ClientMetadataFetchStatusEnum::Unavailable);
        }

        $mediaType = strtolower(trim(explode(';', $response->header('Content-Type'), 2)[0]));

        if ($status !== 200 || ($mediaType !== 'application/json' && ! preg_match('~^application/[a-z0-9.+-]+\+json$~D', $mediaType))) {
            return new ClientMetadataDocumentData(ClientMetadataFetchStatusEnum::Invalid);
        }

        try {
            $document = json_decode($response->body(), false, 32, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            return new ClientMetadataDocumentData(ClientMetadataFetchStatusEnum::Invalid);
        }

        if (! $document instanceof stdClass) {
            return new ClientMetadataDocumentData(ClientMetadataFetchStatusEnum::Invalid);
        }

        $documentFields = array_filter(get_object_vars($document), is_string(...), ARRAY_FILTER_USE_KEY);

        return self::cacheResult($response, ClientMetadataFetchStatusEnum::Fetched, $documentFields);
    }

    /**
     * @param  array<string, mixed>  $document
     */
    private static function cacheResult(Response $response, ClientMetadataFetchStatusEnum $status, array $document = []): ClientMetadataDocumentData
    {
        $cacheControl = $response->header('Cache-Control');
        $hasNoStore = preg_match('/(?:^|,)\s*(?:no-store|private)\b/i', $cacheControl) === 1;
        $maxAgeSeconds = null;

        if (preg_match('/(?:^|,)\s*no-cache\b/i', $cacheControl) === 1) {
            $maxAgeSeconds = 0;
        } elseif (preg_match('/(?:^|,)\s*max-age\s*=\s*(\d+)\s*(?:,|$)/i', $cacheControl, $matches) === 1) {
            $age = $response->header('Age');
            $maxAgeSeconds = max(0, (int) $matches[1] - (ctype_digit($age) ? (int) $age : 0));
        }

        return new ClientMetadataDocumentData($status, $document, self::safeEtag($response->header('ETag')), $maxAgeSeconds, ! $hasNoStore);
    }

    private static function safeEtag(string $etag): ?string
    {
        return strlen($etag) <= 255 && preg_match('/^(?:W\/)?"[\x21\x23-\x7E]*"$/D', $etag) === 1 ? $etag : null;
    }
}
