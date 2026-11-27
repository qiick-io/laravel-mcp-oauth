<?php

declare(strict_types=1);

use Qiick\McpOAuth\Data\GrantRecord;

it('carries public UUID strings and never a bigint id property', function (): void {
    $grant = new GrantRecord(
        id: '550e8400-e29b-41d4-a716-446655440000',
        clientId: '11111111-1111-1111-1111-111111111111',
        userIdentifier: '22222222-2222-2222-2222-222222222222',
        revoked: false,
        scopes: ['mcp:read'],
        authorizedAt: null,
        lastUsedAt: null,
        display: ['role' => 'editor'],
    );

    expect($grant->id)->toBeString()
        ->and($grant->clientId)->toBeString()
        ->and($grant->userIdentifier)->toBeString()
        ->and($grant->scopes)->toBe(['mcp:read'])
        ->and($grant->display)->toBe(['role' => 'editor']);

    $reflection = new ReflectionClass($grant);
    foreach ($reflection->getProperties() as $property) {
        expect($property->getName())->not->toBe('pk')
            ->and($property->getName())->not->toBe('primaryKey');
    }
});
