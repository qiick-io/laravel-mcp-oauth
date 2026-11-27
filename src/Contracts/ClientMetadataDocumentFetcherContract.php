<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Contracts;

use Qiick\McpOAuth\Data\ClientMetadataDocumentData;

/**
 * Fetches a public Client ID Metadata Document under an isolated outbound policy.
 *
 * @api
 */
interface ClientMetadataDocumentFetcherContract
{
    /**
     * Sends a conditional GET when the caller supplies an ETag from a valid document.
     */
    public function fetch(string $metadataDocumentUrl, ?string $etag = null): ClientMetadataDocumentData;
}
