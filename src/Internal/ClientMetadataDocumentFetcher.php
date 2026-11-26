<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Internal;

/**
 * Fetches a Client ID Metadata Document (standards review S2): the JSON a
 * client publishes at the https URL it uses as its `client_id`. The fetch
 * goes through the product's outbound policy (qiick/laravel-outbound, the
 * fleet's one SSRF guard), within `mcp-oauth.cimd.max_document_bytes` and
 * `mcp-oauth.cimd.timeout_seconds`.
 *
 * Not bound and not called yet: CIMD stays off (`supportsClientIdMetadataDocuments()`
 * is false) until its handler lands. Internal until that runtime proves the
 * seam: the caller also needs the response's cache directives (ETag, expiry)
 * and to tell a failed fetch from an invalid document (standards review S2,
 * §2.2), which this shape cannot carry yet (Codex review of #59).
 *
 * @internal
 */
interface ClientMetadataDocumentFetcher
{
    /**
     * @return array<string, mixed>|null the decoded document, or null when the URL is refused, unreachable, too large or not JSON
     */
    public function fetch(string $metadataDocumentUrl): ?array;
}
