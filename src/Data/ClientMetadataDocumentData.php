<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Data;

use Qiick\McpOAuth\Enums\ClientMetadataFetchStatusEnum;

/**
 * The transport result before OAuth client metadata is validated for registration.
 *
 * @api
 */
final readonly class ClientMetadataDocumentData
{
    /**
     * @param  array<string, mixed>  $document  decoded JSON object for a fetched result
     * @param  int|null  $maxAgeSeconds  remaining freshness, or null if the origin gave no cache lifetime
     * @param  bool  $shouldCache  false when the response prohibits storage
     */
    public function __construct(
        public ClientMetadataFetchStatusEnum $status,
        public array $document = [],
        public ?string $etag = null,
        public ?int $maxAgeSeconds = null,
        public bool $shouldCache = true,
    ) {}
}
