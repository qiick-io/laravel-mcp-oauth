<?php

declare(strict_types=1);

use Illuminate\Support\Facades\DB;
use Qiick\McpOAuth\Models\OAuthBlockedRedirectHost;
use Qiick\McpOAuth\Models\OAuthClientMetadata;
use Qiick\McpOAuth\Tests\Http\Server\DatabaseGrantStore;
use Qiick\McpOAuth\Tests\Http\Server\HttpFlowApplication;

/*
 * What an admin does between two requests, with the served app's own
 * configuration (so on every engine): `block-host <host>` and
 * `unblock-host <host>`. The admin routes are tested on their own; here the
 * row matters, not who wrote it.
 */
require __DIR__.'/../../../vendor/autoload.php';

HttpFlowApplication::create();

[, $action, $subject] = $argv;

match ($action) {
    'block-host' => OAuthBlockedRedirectHost::query()->create(['host' => $subject, 'match_mode' => OAuthBlockedRedirectHost::MATCH_MODE_EXACT]),
    'unblock-host' => OAuthBlockedRedirectHost::query()->where('host', $subject)->delete(),
    // The fixture simulates the trusted enrollment in MO4. No HTTP client can assign this class.
    'classify-companion' => OAuthClientMetadata::query()->where('client_id', $subject)->sole()->update(['registration_source' => 'companion']),
    'classify-installation' => OAuthClientMetadata::query()->where('client_id', $subject)->sole()
        ->update(['registration_source' => 'companion', 'has_per_install_grants' => true]),
    'count-active-installations' => print DB::table(DatabaseGrantStore::TABLE)
        ->where('client_id', $subject)->whereNotNull('install_id')->where('revoked', false)->count(),
};
