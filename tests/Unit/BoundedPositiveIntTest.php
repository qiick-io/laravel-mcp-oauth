<?php

declare(strict_types=1);

use Qiick\McpOAuth\Exceptions\InvalidMcpOAuthConfigException;
use Qiick\McpOAuth\Internal\BoundedPositiveInt;

/**
 * Strict digit-only TTL parsing: rejects forms that `(int) env(...)` would
 * silently coerce (floats, scientific notation, signed strings).
 */
dataset('rejected_ttl_values', [
    'float string' => ['1.5'],
    'scientific lowercase' => ['1e3'],
    'scientific uppercase' => ['1E2'],
    'scientific with plus exponent' => ['1e+2'],
    'leading plus' => ['+60'],
    'leading minus string' => ['-5'],
    'leading space' => [' 60'],
    'trailing space' => ['60 '],
    'empty string' => [''],
    'decimal zero' => ['60.0'],
    'hex-looking' => ['0x10'],
    'null' => [null],
    'bool true' => [true],
    'float value' => [1.5],
    'negative int' => [-5],
    'zero int' => [0],
    'over max int' => [1_441],
]);

dataset('accepted_ttl_values', [
    'digit string' => ['60', 60],
    'max digit string' => ['1440', 1_440],
    'positive int' => [60, 60],
    'max int' => [1_440, 1_440],
]);

it('accepts digit strings and in-range integers', function (mixed $value, int $expected): void {
    expect(BoundedPositiveInt::require($value, 'access_token_ttl_minutes', BoundedPositiveInt::ACCESS_TOKEN_TTL_MINUTES_MAX))
        ->toBe($expected);
})->with('accepted_ttl_values');

it('rejects float, scientific, signed, blank and out-of-range values', function (mixed $value): void {
    expect(fn () => BoundedPositiveInt::require(
        $value,
        'access_token_ttl_minutes',
        BoundedPositiveInt::ACCESS_TOKEN_TTL_MINUTES_MAX,
    ))->toThrow(InvalidMcpOAuthConfigException::class);
})->with('rejected_ttl_values');

it('rejects env-like float and scientific strings that (int) would coerce', function (): void {
    expect((int) '1.5')->toBe(1)
        ->and((int) '1e2')->toBe(100);

    expect(fn () => BoundedPositiveInt::require('1.5', 'access_token_ttl_minutes', 1_440))
        ->toThrow(InvalidMcpOAuthConfigException::class);

    expect(fn () => BoundedPositiveInt::require('1e2', 'access_token_ttl_minutes', 1_440))
        ->toThrow(InvalidMcpOAuthConfigException::class);
});
