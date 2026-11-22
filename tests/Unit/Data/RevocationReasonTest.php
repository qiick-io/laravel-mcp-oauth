<?php

declare(strict_types=1);

use Qiick\McpOAuth\Data\RevocationReason;

it('exposes the design wire values', function (): void {
    expect(RevocationReason::User->value)->toBe('user')
        ->and(RevocationReason::Admin->value)->toBe('admin')
        ->and(RevocationReason::Reuse->value)->toBe('reuse')
        ->and(RevocationReason::Reconsent->value)->toBe('reconsent')
        ->and(RevocationReason::Owner->value)->toBe('owner');
});
