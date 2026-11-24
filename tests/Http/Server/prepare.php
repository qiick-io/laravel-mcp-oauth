<?php

declare(strict_types=1);

use Illuminate\Support\Facades\DB;
use Qiick\McpOAuth\Tests\Http\Server\HttpFlowApplication;
use Qiick\McpOAuth\Tests\Http\Server\HttpFlowSchema;

/*
 * Run once before the server starts: a fresh schema and one verified user,
 * with the configuration the served app uses.
 */
require __DIR__.'/../../../vendor/autoload.php';

HttpFlowApplication::create();
HttpFlowSchema::create();
DB::table('users')->insert(['id' => 1, 'email_verified_at' => now(), 'created_at' => now(), 'updated_at' => now()]);
