<?php

declare(strict_types=1);

use Qiick\McpOAuth\Data\ConsentDecision;
use Qiick\McpOAuth\Data\GrantInstallationData;
use Qiick\McpOAuth\Data\GrantRecord;
use Qiick\McpOAuth\Data\RevocationReason;
use Qiick\McpOAuth\Testing\FakeGrantStore;
use Qiick\McpOAuth\Tests\Support\TestUser;

/** Seed a complete grant snapshot for the product adapter exercise. */
function fakeStoreGrant(
    string $identifier,
    string $clientId = 'client',
    string $userIdentifier = 'user',
    bool $isRevoked = false,
    ?GrantInstallationData $installation = null,
): GrantRecord {
    return new GrantRecord($identifier, $clientId, $userIdentifier, $isRevoked, ['read'], null, null, installation: $installation);
}

it('finds the newest active grant and retires it on renewed consent', function (): void {
    $store = new FakeGrantStore;
    $earlierGrant = fakeStoreGrant('earlier');
    $latestGrant = fakeStoreGrant('latest');
    $store->seed($earlierGrant);
    $store->seed($latestGrant);
    $store->seed(fakeStoreGrant('other-user', userIdentifier: 'other'));
    $store->seed(fakeStoreGrant('revoked', isRevoked: true));

    expect($store->activeFor('client', 'user'))->toBe($latestGrant);

    $decision = new ConsentDecision('client', 'user', 'https://app.example/callback', ['read'], 'reader', ['docs'], false);
    $replacement = $store->replace($decision);

    expect($store->find($latestGrant->id)?->revoked)->toBeTrue()
        ->and($store->activeFor('client', 'user'))->toBe($replacement)
        ->and($replacement->display)->toBe(['role' => 'reader', 'resources' => ['docs']])
        ->and($store->revocations)->toBe([
            ['grantId' => $latestGrant->id, 'actorIdentifier' => 'user', 'reason' => RevocationReason::Reconsent],
        ])
        ->and($store->replacedDecisions)->toBe([$decision]);
});

it('replaces the first matching active installation across all grant dimensions', function (): void {
    $store = new FakeGrantStore;
    $installation = new GrantInstallationData('installation', 'thumbprint', 'organisation');
    $replacementInstallation = new GrantInstallationData('installation', 'new-thumbprint', 'organisation');
    $otherOrganisation = new GrantInstallationData('installation', 'thumbprint', 'another-organisation');
    $otherInstallation = new GrantInstallationData('other-installation', 'thumbprint', 'organisation');
    $previous = fakeStoreGrant('previous', installation: $installation);
    $otherGrants = [
        fakeStoreGrant('legacy'),
        fakeStoreGrant('revoked', isRevoked: true, installation: $installation),
        fakeStoreGrant('other-client', clientId: 'different', installation: $installation),
        fakeStoreGrant('other-user', userIdentifier: 'different', installation: $installation),
        fakeStoreGrant('other-organisation', installation: $otherOrganisation),
        fakeStoreGrant('other-installation', installation: $otherInstallation),
    ];

    foreach ([...$otherGrants, $previous, fakeStoreGrant('duplicate', installation: $installation)] as $grant) {
        $store->seed($grant);
    }

    $decision = new ConsentDecision(
        'client', 'user', 'https://app.example/callback', ['read'], null, [], false,
        resourceScopes: ['https://app.example/companion' => 'companion:device'],
        installation: $replacementInstallation,
    );
    $replacement = $store->replaceForInstallation($decision);

    expect($replacement->previousGrant)->toBe($previous)
        ->and($replacement->grant->installation)->toBe($replacementInstallation)
        ->and($replacement->grant->resourceScopes)->toBe($decision->resourceScopes)
        ->and($store->find($previous->id)?->revoked)->toBeTrue();

    foreach ($otherGrants as $grant) {
        expect($store->find($grant->id))->toBe($grant);
    }
});

it('requires a decision with an installation for installation reconsent', function (): void {
    $decision = new ConsentDecision('client', 'user', 'https://app.example/callback', [], null, [], false);

    expect(fn () => (new FakeGrantStore)->replaceForInstallation($decision))
        ->toThrow(LogicException::class, 'The decision is missing an installation.');
});

it('retains grant evidence until its revocation is strictly older than the purge cutoff', function (): void {
    $this->freezeSecond();
    $revokedAt = now()->toDateTimeImmutable();
    $authorizedAt = $revokedAt->modify('-1 day');
    $installation = new GrantInstallationData('installation', 'thumbprint');
    $approvedScopes = ['https://app.example/mcp' => 'mcp:use'];
    $grant = new GrantRecord(
        'selected', 'client', 'user', false, ['read'], $authorizedAt, $authorizedAt,
        display: ['role' => 'reader'], metadata: ['source' => 'fixture'],
        resourceScopes: $approvedScopes, installation: $installation,
    );
    $otherClientGrant = fakeStoreGrant('other-client', clientId: 'another-client');
    $otherRevokedGrant = fakeStoreGrant('other-revoked', isRevoked: true);
    $store = new FakeGrantStore;
    $store->seed($grant);
    $store->seed($otherClientGrant);
    $store->seed($otherRevokedGrant);

    $store->revokeAllForClient('client', 'administrator');
    $revoked = $store->find($grant->id);

    expect($store->revocations)->toBe([
        ['grantId' => $grant->id, 'actorIdentifier' => 'administrator', 'reason' => RevocationReason::Admin],
    ])->and($revoked?->revoked)->toBeTrue()
        ->and($revoked?->scopes)->toBe($grant->scopes)
        ->and($revoked?->authorizedAt)->toBe($authorizedAt)
        ->and($revoked?->lastUsedAt)->toBe($authorizedAt)
        ->and($revoked?->revokedAt)->toEqual($revokedAt)
        ->and($revoked?->revocationReason)->toBe(RevocationReason::Admin)
        ->and($revoked?->installation)->toBe($installation)
        ->and($revoked?->resourceScopes)->toBe($approvedScopes)
        ->and($revoked?->display)->toBe($grant->display)
        ->and($revoked?->metadata)->toBe($grant->metadata)
        ->and($store->find($otherClientGrant->id))->toBe($otherClientGrant)
        ->and($store->purgeRevokedBefore($revokedAt))->toBe(0)
        ->and($store->purgeRevokedBefore($revokedAt->modify('+1 second')))->toBe(1)
        ->and($store->find($grant->id))->toBeNull();
});

it('lists distinct historical clients and active grants for the selected user', function (): void {
    $store = new FakeGrantStore;
    $firstGrant = fakeStoreGrant('first', userIdentifier: '42');
    $secondGrant = fakeStoreGrant('second', userIdentifier: '42');
    $otherGrant = fakeStoreGrant('other', clientId: 'other-client', userIdentifier: 'another-user');
    $revokedGrant = fakeStoreGrant('revoked', clientId: 'revoked-client', userIdentifier: '42', isRevoked: true);

    foreach ([$firstGrant, $secondGrant, $otherGrant, $revokedGrant] as $grant) {
        $store->seed($grant);
    }

    $integerPrincipal = (new TestUser)->forceFill(['id' => 42]);
    $stringPrincipal = (new TestUser)->setKeyType('string')->forceFill(['id' => '42']);
    expect($store->everAuthorized(['client', 'revoked-client', 'unknown-client']))->toBe(['client', 'revoked-client'])
        ->and($store->activeForUser($integerPrincipal))->toBe([$firstGrant, $secondGrant])
        ->and($store->activeForUser($stringPrincipal))->toBe([$firstGrant, $secondGrant])
        ->and($store->activeForUser(new TestUser))->toBe([]);
});
