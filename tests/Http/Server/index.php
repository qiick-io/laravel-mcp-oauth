<?php

declare(strict_types=1);

use Illuminate\Http\Request;
use Qiick\McpOAuth\Tests\Http\Server\HttpFlowApplication;

/*
 * Router script for `php -S`: every request boots the test product app.
 */
require __DIR__.'/../../../vendor/autoload.php';

HttpFlowApplication::create()->handleRequest(Request::capture());
