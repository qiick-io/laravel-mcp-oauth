<?php

declare(strict_types=1);

use Qiick\McpOAuth\Tests\Support\AuthorizeFlowTestCase;
use Qiick\McpOAuth\Tests\Support\PackageTestCase;

/*
 * Fleet conformance under tests/Conformance is app-scoped (needs a product
 * TestCase + migrated schema). phpunit.xml excludes that directory so the
 * synced suite stays for drift-check without running here.
 */
// Not tests/Http: those drive real `php -S` servers, and PackageTestCase
// would drop and recreate the tables they share on a server engine.
pest()->extend(PackageTestCase::class)->in('Feature', 'Unit');
pest()->extend(AuthorizeFlowTestCase::class)->in('Erasure');
