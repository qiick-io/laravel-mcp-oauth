<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Contracts;

use Qiick\McpOAuth\Data\ConsentDecision;
use Qiick\McpOAuth\Data\GrantReplacementData;

/**
 * Opt-in extension for stores that give each Companion installation its own grant.
 *
 * @api
 */
interface InstallationGrantStoreContract extends GrantStore
{
    /**
     * Atomically replace only the active grant for the decision's exact
     * (client, principal, organisation, installation) tuple and return its
     * prior grant, if any, for credential retirement. Persist the thumbprint
     * and consent time on the new grant. Every read and erasure path includes
     * grants created through this extension. Reads of revoked grants include
     * the stored reason, so an expiry can be distinguished from reuse.
     */
    public function replaceForInstallation(ConsentDecision $decision): GrantReplacementData;
}
