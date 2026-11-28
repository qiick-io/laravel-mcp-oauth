<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Data;

/**
 * The installation and key thumbprint approved for one Companion account.
 * The organisation comes from the trusted consent choice for that account.
 *
 * @api
 */
final readonly class GrantInstallationData
{
    public function __construct(
        public string $installId,
        public string $keyThumbprint,
        public ?string $organisationId = null,
    ) {}
}
