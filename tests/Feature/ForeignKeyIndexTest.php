<?php

declare(strict_types=1);

use Qiick\Standards\Conformance\Support\SchemaInspector;

/*
 * Fleet F8/C76 requires an index to serve each foreign key so the database
 * can find child rows when a parent row changes. PackageTestCase migrates the
 * package tables and their users dependency on each engine in the CI matrix.
 * Source: https://github.com/qiick-io/app-ui/blob/v0.15.0/standards/php/ForeignKeyIndexTest.php
 */
require_once __DIR__.'/../Conformance/Support/SchemaInspector.php';

it('serves every foreign key with an index', function (): void {
    expect((new SchemaInspector)->foreignKeysWithoutIndex())->toBe([]);
});
