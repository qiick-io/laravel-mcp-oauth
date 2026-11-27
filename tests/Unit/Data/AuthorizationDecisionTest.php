<?php

declare(strict_types=1);

use Qiick\McpOAuth\Data\AuthorizationDecision;

it('allows without an error code', function (): void {
    $decision = AuthorizationDecision::allow();

    expect($decision->isAllowed)->toBeTrue()
        ->and($decision->error)->toBeNull()
        ->and($decision->description)->toBeNull()
        ->and($decision->scope)->toBeNull();
});

it('names invalid_token for a 401 refusal', function (): void {
    $decision = AuthorizationDecision::invalidToken('expired');

    expect($decision->isAllowed)->toBeFalse()
        ->and($decision->error)->toBe('invalid_token')
        ->and($decision->description)->toBe('expired')
        ->and($decision->scope)->toBeNull();
});

it('names insufficient_scope and the scope for a 403 refusal', function (): void {
    $decision = AuthorizationDecision::insufficientScope('mcp:read', 'grant lacks mcp:read');

    expect($decision->isAllowed)->toBeFalse()
        ->and($decision->error)->toBe('insufficient_scope')
        ->and($decision->description)->toBe('grant lacks mcp:read')
        ->and($decision->scope)->toBe('mcp:read');
});
