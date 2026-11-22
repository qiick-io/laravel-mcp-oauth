<?php

declare(strict_types=1);

use Qiick\McpOAuth\Exceptions\MissingPassportKeysException;

it('names passport:keys and the PASSPORT_* env vars', function (): void {
    $exception = MissingPassportKeysException::make();

    expect($exception->getMessage())->toContain('passport:keys')
        ->and($exception->getMessage())->toContain('PASSPORT_PRIVATE_KEY')
        ->and($exception->getMessage())->toContain('PASSPORT_PUBLIC_KEY');
});
