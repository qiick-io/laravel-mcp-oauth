<?php

declare(strict_types=1);

use Qiick\McpOAuth\Tests\Support\MigrationLoadDisabledTestCase;

uses(MigrationLoadDisabledTestCase::class);

it('does not register package migration paths when mcp-oauth.migrations.load is false', function (): void {
    expect(config('mcp-oauth.migrations.load'))->toBeFalse();

    $packageMigrationsPath = realpath(dirname(__DIR__, 2).'/database/migrations');

    expect($packageMigrationsPath)->not->toBeFalse()
        ->and(
            collect(app('migrator')->paths())
                ->map(static fn (string $path): string|false => realpath($path))
                ->filter()
                ->contains($packageMigrationsPath),
        )->toBeFalse();
});
