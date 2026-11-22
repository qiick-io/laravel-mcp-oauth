<?php

declare(strict_types=1);

/**
 * Package-only architecture rules. Naming, suffixes, strict types and readonly
 * DTOs are the shared qiick rules in NamingArchitectureTest.php (configured in
 * naming-architecture.php). Feature PRs add parse_url / Signaculum / @api
 * surface freezes from the design.
 */
arch('src never imports Illuminate Foundation types')
    ->expect('Qiick\McpOAuth')
    ->not->toUse('Illuminate\Foundation');
