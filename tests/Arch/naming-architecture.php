<?php

declare(strict_types=1);

/**
 * This repo's settings for the shared `NamingArchitectureTest.php` (qiick standards).
 *
 * Written once by the sync, never overwritten or checked: it is this repo's own.
 * Package-only rules (no Foundation / parse_url / Signaculum in src/, @api surface)
 * are in `PackageArchitectureTest.php`.
 *
 * Public API names follow the binding design (not the shared Contract/Enum suffix
 * table): design-mandated types are listed under ignoring with reasons as they land.
 */
return [
    'namespace' => 'Qiick\McpOAuth',

    'ignoring' => [
        // Feature PRs add design §3 / §5 types that omit shared suffixes.
    ],

    'suffixes' => [],

    'controllerPublicMethods' => [],
];
