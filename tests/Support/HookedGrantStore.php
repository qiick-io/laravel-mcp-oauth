<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Tests\Support;

use Closure;
use Illuminate\Contracts\Auth\Authenticatable;
use Qiick\McpOAuth\Contracts\GrantStore;
use Qiick\McpOAuth\Data\ConsentDecision;
use Qiick\McpOAuth\Data\GrantRecord;
use Qiick\McpOAuth\Data\RevocationReason;
use Qiick\McpOAuth\Testing\FakeGrantStore;

/**
 * Wraps a FakeGrantStore and runs a hook at one moment of a request, to
 * reproduce what a concurrent request would do in between: a new consent
 * right after a code is consumed, or a look at the tokens when a grant is
 * revoked.
 */
final class HookedGrantStore implements GrantStore
{
    /** Runs once, after the next activeFor(). */
    public ?Closure $afterNextActiveFor = null;

    /** @var Closure(string): void|null runs before every revoke(), with the grant id */
    public ?Closure $beforeRevoke = null;

    public function __construct(
        public readonly FakeGrantStore $grantStore,
    ) {}

    public function find(string $grantId): ?GrantRecord
    {
        return $this->grantStore->find($grantId);
    }

    public function activeFor(string $clientId, string $userIdentifier): ?GrantRecord
    {
        $grant = $this->grantStore->activeFor($clientId, $userIdentifier);
        $hook = $this->afterNextActiveFor;
        $this->afterNextActiveFor = null;

        if ($hook !== null) {
            $hook();
        }

        return $grant;
    }

    public function replace(ConsentDecision $decision): GrantRecord
    {
        return $this->grantStore->replace($decision);
    }

    public function revoke(string $grantId, ?string $actorIdentifier, RevocationReason $reason): void
    {
        if ($this->beforeRevoke !== null) {
            ($this->beforeRevoke)($grantId);
        }

        $this->grantStore->revoke($grantId, $actorIdentifier, $reason);
    }

    public function revokeAllForClient(string $clientId, ?string $actorIdentifier): void
    {
        $this->grantStore->revokeAllForClient($clientId, $actorIdentifier);
    }

    public function everAuthorized(array $clientIds): array
    {
        return $this->grantStore->everAuthorized($clientIds);
    }

    public function activeForUser(Authenticatable $user): array
    {
        return $this->grantStore->activeForUser($user);
    }

    public function bindingKey(GrantRecord $grant): string|int
    {
        return $this->grantStore->bindingKey($grant);
    }
}
