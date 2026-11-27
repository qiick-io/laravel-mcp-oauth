# 2026-11-26: The CIMD fetcher stays internal until its runtime lands

**Decided by:** the maintainer, accepting the security review of the M9 contracts.

**Decision.** `ClientMetadataDocumentFetcher` ships as `Qiick\McpOAuth\Internal\ClientMetadataDocumentFetcher`, marked `@internal`, not as a public contract. CIMD stays off (`supportsClientIdMetadataDocuments()` is false) until the fetch runs through `qiick/laravel-outbound`.

**Why.** Its `?array` result cannot carry what the caller needs: the response's cache directives (ETag, expiry) for the bounded cache the standards review requires, and the difference between a failed fetch and an invalid document. Nothing can test that cache contract before the runtime exists, and freezing the shape now would force a break later.

**Consequences.** The interface becomes `@api`, with a typed result, in the release that turns CIMD on (between the beta and 1.0).
