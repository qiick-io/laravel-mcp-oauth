<?php

declare(strict_types=1);

use Qiick\McpOAuth\Models\OAuthBlockedRedirectHost;
use Qiick\McpOAuth\Tests\Http\Server\HttpFlowApplication;

/*
 * What an admin does between two requests, with the served app's own
 * configuration (so on every engine): `block-host <host>` and
 * `unblock-host <host>`. The admin routes are tested on their own; here the
 * row matters, not who wrote it.
 */
require __DIR__.'/../../../vendor/autoload.php';

HttpFlowApplication::create();

[, $action, $host] = $argv;

match ($action) {
    'block-host' => OAuthBlockedRedirectHost::query()->create(['host' => $host, 'match_mode' => OAuthBlockedRedirectHost::MATCH_MODE_EXACT]),
    'unblock-host' => OAuthBlockedRedirectHost::query()->where('host', $host)->delete(),
};
