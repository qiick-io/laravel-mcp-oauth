<?php

declare(strict_types=1);

use Illuminate\Console\Scheduling\Event as ScheduledEvent;
use Illuminate\Console\Scheduling\Schedule;
use Qiick\McpOAuth\Tests\Support\AuthorizeFlowTestCase;

uses(AuthorizeFlowTestCase::class);

/**
 * The package schedules its own retention commands (fleet convention F9):
 * on one server, never overlapping, behind `mcp-oauth.retention.schedule`,
 * and only while `mcp-oauth.enabled` is on (F3: off registers nothing).
 */

/**
 * @return array<string, ScheduledEvent> the package's scheduled commands by name
 */
function scheduledRetentionCommands(): array
{
    $scheduledCommands = [];

    foreach (app(Schedule::class)->events() as $scheduledEvent) {
        if (preg_match('/(mcp-oauth:[a-z-]+)/', (string) $scheduledEvent->command, $match) === 1) {
            $scheduledCommands[$match[1]] = $scheduledEvent;
        }
    }

    ksort($scheduledCommands);

    return $scheduledCommands;
}

it('schedules every retention command on one server, without overlapping', function (): void {
    config()->set('mcp-oauth.enabled', true);

    $scheduledCommands = scheduledRetentionCommands();

    expect(array_keys($scheduledCommands))->toBe(['mcp-oauth:prune-auth-code-exchanges', 'mcp-oauth:prune-unused-clients', 'mcp-oauth:purge-revoked'])
        ->and($scheduledCommands['mcp-oauth:prune-auth-code-exchanges']->expression)->toBe('0 0 * * *')
        ->and($scheduledCommands['mcp-oauth:purge-revoked']->expression)->toBe('0 0 * * *')
        ->and($scheduledCommands['mcp-oauth:prune-unused-clients']->expression)->toBe('0 * * * *');

    foreach ($scheduledCommands as $scheduledCommand) {
        expect($scheduledCommand->onOneServer)->toBeTrue()
            ->and($scheduledCommand->withoutOverlapping)->toBeTrue();
    }
});

it('schedules them from a config published before the retention key existed (F1)', function (): void {
    config()->set('mcp-oauth.enabled', true);
    $publishedConfig = config('mcp-oauth');
    unset($publishedConfig['retention']);
    config()->set('mcp-oauth', $publishedConfig);

    expect(scheduledRetentionCommands())->toHaveCount(3);
});

it('schedules nothing while OAuth is off in config (F3) or the product schedules them itself', function (bool $isEnabled, bool $shouldSchedule): void {
    config()->set('mcp-oauth.enabled', $isEnabled);
    config()->set('mcp-oauth.retention.schedule', $shouldSchedule);

    expect(scheduledRetentionCommands())->toBe([]);
})->with([
    'OAuth off' => [false, true],
    'schedule switched off' => [true, false],
]);
