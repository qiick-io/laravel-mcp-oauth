<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Data;

use DateTimeImmutable;

/**
 * Product grant as the package sees it. Ids are public UUID strings.
 *
 * @api
 */
final readonly class GrantRecord
{
    /**
     * @param  list<string>  $scopes
     * @param  array<string, scalar|list<scalar>|null>  $display
     * @param  array<string, scalar|list<scalar>|null>  $metadata  the product's own fields
     * @param  array<string, string>  $resourceScopes  immutable audience to wire scope pairs copied from the decision
     */
    public function __construct(
        public string $id,
        public string $clientId,
        public string $userIdentifier,
        public bool $revoked,
        public array $scopes,
        public ?DateTimeImmutable $authorizedAt,
        public ?DateTimeImmutable $lastUsedAt,
        public array $display = [],
        public ?DateTimeImmutable $revokedAt = null,
        public ?RevocationReason $revocationReason = null,
        public array $metadata = [],
        public array $resourceScopes = [],
        public ?GrantInstallationData $installation = null,
    ) {}
}
