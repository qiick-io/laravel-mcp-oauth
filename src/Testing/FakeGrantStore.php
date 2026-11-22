<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Testing;

use DateTimeImmutable;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Str;
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

    /** @var list<ConsentDecision> decisions passed to replace(), oldest first */
    public array $replacedDecisions = [];

    /**
     * Revokes the active grant for (client, user) with RevocationReason::Reconsent,
     * then stores a new active grant built from the decision.
     */
    public function replace(ConsentDecision $decision): GrantRecord
    {
        $this->replacedDecisions[] = $decision;
        $earlierGrant = $this->activeFor($decision->clientId, $decision->userIdentifier);

        if ($earlierGrant !== null) {
            $this->revoke($earlierGrant->id, $decision->userIdentifier, RevocationReason::Reconsent);
        }

        $grant = new GrantRecord(
            id: (string) Str::uuid7(),
            clientId: $decision->clientId,
            userIdentifier: $decision->userIdentifier,
            revoked: false,
            scopes: $decision->scopes,
            authorizedAt: new DateTimeImmutable,
            lastUsedAt: null,
            display: ['role' => $decision->role, 'resources' => $decision->resources],
        );
        $this->grantsById[$grant->id] = $grant;

        return $grant;
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
