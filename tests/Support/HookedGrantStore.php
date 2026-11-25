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
 * right after a code is consumed, a replay of the code while the winner binds
 * its token, or a look at the tokens when a grant is revoked.
 */
final class HookedGrantStore implements GrantStore
{
    /** Runs once, after the next activeFor(). */
    public ?Closure $afterNextActiveFor = null;

    /** Runs once, before the next find() reads the grant. */
    public ?Closure $beforeNextFind = null;

    /** Runs once, after the next find() has read the grant and before it returns it. */
    public ?Closure $afterNextFind = null;

    /** When true, find() answers as if the product had deleted the grant. */
    public bool $isGrantGone = false;

    /** @var Closure(string): void|null runs before every revoke(), with the grant id */
    public ?Closure $beforeRevoke = null;

    public function __construct(
        public readonly FakeGrantStore $grantStore,
    ) {}

    public function find(string $grantId): ?GrantRecord
    {
        $beforeHook = $this->beforeNextFind;
        $this->beforeNextFind = null;

        if ($beforeHook !== null) {
            $beforeHook();
        }

        $grant = $this->isGrantGone ? null : $this->grantStore->find($grantId);
        $afterHook = $this->afterNextFind;
        $this->afterNextFind = null;

        if ($afterHook !== null) {
            $afterHook();
        }

        return $grant;
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

    /** Runs once, before the next replace(), inside the approval's transaction. */
    public ?Closure $beforeNextReplace = null;

    public function replace(ConsentDecision $decision): GrantRecord
    {
        $hook = $this->beforeNextReplace;
        $this->beforeNextReplace = null;

        if ($hook !== null) {
            $hook();
        }

        return $this->grantStore->replace($decision);
    }

    public function revoke(string $grantId, ?string $actorIdentifier, RevocationReason $reason): void
    {
        if ($this->beforeRevoke !== null) {
            ($this->beforeRevoke)($grantId);
        }

        $this->grantStore->revoke($grantId, $actorIdentifier, $reason);
    }

    public function purgeRevokedBefore(\DateTimeImmutable $cutoff): int
    {
        return $this->grantStore->purgeRevokedBefore($cutoff);
    }

    public function revokeAllForClient(string $clientId, ?string $actorIdentifier): void
    {
        $this->grantStore->revokeAllForClient($clientId, $actorIdentifier);
    }

    /** @var list<int> how many client ids each everAuthorized() call was asked about */
    public array $everAuthorizedBatchSizes = [];

    /** Runs once, after the next everAuthorized() has answered. */
    public ?Closure $afterNextEverAuthorized = null;

    public function everAuthorized(array $clientIds): array
    {
        $this->everAuthorizedBatchSizes[] = count($clientIds);
        $authorizedClientIds = $this->grantStore->everAuthorized($clientIds);
        $hook = $this->afterNextEverAuthorized;
        $this->afterNextEverAuthorized = null;

        if ($hook !== null) {
            $hook();
        }

        return $authorizedClientIds;
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
