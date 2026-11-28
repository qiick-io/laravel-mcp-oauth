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
    /** @internal Carries only a validated, server-owned authorization request. */
    public const string REQUEST_ATTRIBUTE = 'mcp_oauth_grant_installation';

    /** @internal Hands the approved grant to Passport while it issues its code. */
    public const string APPROVED_GRANT_ATTRIBUTE = 'mcp_oauth_approved_installation_grant';

    public function __construct(
        public string $installId,
        public string $keyThumbprint,
        public ?string $organisationId = null,
    ) {}

    public function hasSameAccountAs(self $installation): bool
    {
        return $this->installId === $installation->installId && $this->organisationId === $installation->organisationId;
    }
}
