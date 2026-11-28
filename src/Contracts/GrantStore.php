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
    /**
     * A fresh read of committed state, from the primary, never cached or
     * memoised: the package reads a grant again right after binding a token
     * to catch a concurrent revocation (BindAccessTokenAction).
     */
    public function find(string $grantId): ?GrantRecord;

    /**
     * The newest active grant for this client and user, or null.
     */
    public function activeFor(string $clientId, string $userIdentifier): ?GrantRecord;

    /**
     * In one transaction with a row lock: revoke the active grant for
     * (client, user) in place, then create and return the new one. The package
     * revokes Passport credentials afterwards.
     *
     * Products that register extra protected resources persist the decision's
     * immutable resource-to-scope pairs on the grant and return them on reads.
     */
    public function replace(ConsentDecision $decision): GrantRecord;

    /**
     * Idempotent: revoking a revoked grant changes nothing.
     *
     * The package calls it last in a transaction on Passport's connection,
     * after the token changes and the audit entry, holding the client's row
     * lock (Connected apps, RFC 7009). A store on that connection rolls back
     * with them; one that commits on its own is written only once everything
     * before it succeeded, so a failed audit never leaves a revoked grant
     * without its entry. If Passport's transaction then fails (its commit),
     * the package writes the tokens and the entry again in a new one and
     * reports the failure: a revoked grant is never un-revoked, the revoke
     * completes forward. The same connection keeps all of it in one commit.
     */
    public function revoke(string $grantId, ?string $actorIdentifier, RevocationReason $reason): void;

    public function revokeAllForClient(string $clientId, ?string $actorIdentifier): void;

    /**
     * Retention (standards review M5): delete the grants revoked before the
     * cutoff (90 days ago by default) and return how many went. The product
     * may keep rows it holds for its own reasons, such as a legal hold; the
     * package never decides that.
     */
    public function purgeRevokedBefore(\DateTimeImmutable $cutoff): int;

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
     * Internal key written to the token binding column (may be the product PK
     * and never leaves the database). Its string value also resolves the
     * grant through find(), so an existing token retains its exact grant.
     */
    public function bindingKey(GrantRecord $grant): string|int;
}
