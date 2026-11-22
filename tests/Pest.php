<?php

declare(strict_types=1);

use Qiick\McpOAuth\Tests\Support\PackageTestCase;

/*
 * Fleet conformance under tests/Conformance is app-scoped (needs a product
 * TestCase + migrated schema). phpunit.xml excludes that directory so the
 * synced suite stays for drift-check without running here.
 */
pest()->extend(PackageTestCase::class)->in('Feature', 'Unit', 'Http');
