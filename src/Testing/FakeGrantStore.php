<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Testing;

use Illuminate\Contracts\Auth\Authenticatable;
use LogicException;
use Qiick\McpOAuth\Contracts\GrantStore;
use Qiick\McpOAuth\Data\ConsentDecision;
use Qiick\McpOAuth\Data\GrantRecord;
use Qiick\McpOAuth\Data\RevocationReason;

/**
 * In-memory {@see GrantStore} for package tests and product fakes.
 *
 * @api
 */
final class FakeGrantStore implements GrantStore
{
    /** @var array<string, GrantRecord> */
    private array $grantsById = [];

    /** @var list<array{grantId: string, actorIdentifier: ?string, reason: RevocationReason}> */
    public array $revocations = [];

    public function seed(GrantRecord $grant): void
    {
        $this->grantsById[$grant->id] = $grant;
    }

    public function find(string $grantId): ?GrantRecord
    {
        return $this->grantsById[$grantId] ?? null;
    }

    public function activeFor(string $clientId, string $userIdentifier): ?GrantRecord
    {
        $matchingGrants = array_values(array_filter(
            $this->grantsById,
            static fn (GrantRecord $grant): bool => ! $grant->revoked
                && $grant->clientId === $clientId
                && $grant->userIdentifier === $userIdentifier,
        ));

        return $matchingGrants === [] ? null : $matchingGrants[array_key_last($matchingGrants)];
    }

    public function replace(ConsentDecision $decision): GrantRecord
    {
        throw new LogicException('FakeGrantStore::replace() is not used by family-revoke tests.');
    }

    public function revoke(string $grantId, ?string $actorIdentifier, RevocationReason $reason): void
    {
        $this->revocations[] = [
            'grantId' => $grantId,
            'actorIdentifier' => $actorIdentifier,
            'reason' => $reason,
        ];

        $existingGrant = $this->grantsById[$grantId] ?? null;

        if ($existingGrant === null || $existingGrant->revoked) {
            return;
        }

        $this->grantsById[$grantId] = new GrantRecord(
            id: $existingGrant->id,
            clientId: $existingGrant->clientId,
            userIdentifier: $existingGrant->userIdentifier,
            revoked: true,
            scopes: $existingGrant->scopes,
            authorizedAt: $existingGrant->authorizedAt,
            lastUsedAt: $existingGrant->lastUsedAt,
            display: $existingGrant->display,
        );
    }

    public function revokeAllForClient(string $clientId, ?string $actorIdentifier): void
    {
        foreach ($this->grantsById as $grant) {
            if ($grant->clientId === $clientId && ! $grant->revoked) {
                $this->revoke($grant->id, $actorIdentifier, RevocationReason::Admin);
            }
        }
    }

    public function everAuthorized(array $clientIds): array
    {
        $authorizedClientIds = [];

        foreach ($this->grantsById as $grant) {
            if (in_array($grant->clientId, $clientIds, true)) {
                $authorizedClientIds[] = $grant->clientId;
            }
        }

        return array_values(array_unique($authorizedClientIds));
    }

    public function activeForUser(Authenticatable $user): array
    {
        $authIdentifier = $user->getAuthIdentifier();
        $userIdentifier = is_string($authIdentifier)
            ? $authIdentifier
            : (is_int($authIdentifier) ? (string) $authIdentifier : '');

        return array_values(array_filter(
            $this->grantsById,
            static fn (GrantRecord $grant): bool => ! $grant->revoked
                && $grant->userIdentifier === $userIdentifier,
        ));
    }

    public function bindingKey(GrantRecord $grant): string
    {
        return $grant->id;
    }
}
