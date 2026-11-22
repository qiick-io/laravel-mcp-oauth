<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Qiick\McpOAuth\Data\ConsentDecision;
use Qiick\McpOAuth\Data\GrantRecord;
use Qiick\McpOAuth\Data\RevocationReason;

/**
 * Product-owned grant rows. Ids are public UUID strings.
 *
 * @api
 */
interface GrantStore
{
    public function find(string $grantId): ?GrantRecord;

    /**
     * The newest active grant for this client and user, or null.
     */
    public function activeFor(string $clientId, string $userIdentifier): ?GrantRecord;

    /**
     * In one transaction with a row lock: revoke the active grant for
     * (client, user) in place, then create and return the new one. The package
     * revokes Passport credentials afterwards.
     */
    public function replace(ConsentDecision $decision): GrantRecord;

    /**
     * Idempotent: revoking a revoked grant changes nothing.
     */
    public function revoke(string $grantId, ?string $actorIdentifier, RevocationReason $reason): void;

    public function revokeAllForClient(string $clientId, ?string $actorIdentifier): void;

    /**
     * @param  list<string>  $clientIds
     * @return list<string> those with any grant ever (revoked included)
     */
    public function everAuthorized(array $clientIds): array;

    /**
     * @return list<GrantRecord> active grants of this user (Connected apps)
     */
    public function activeForUser(Authenticatable $user): array;

    /**
     * Internal key written to the token binding column (may be the product PK;
     * never leaves the DB).
     */
    public function bindingKey(GrantRecord $grant): string|int;
}
