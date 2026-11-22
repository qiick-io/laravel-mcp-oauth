<?php

declare(strict_types=1);

/**
 * Package-only architecture rules. Naming, suffixes, strict types and readonly
 * DTOs are the shared qiick rules in NamingArchitectureTest.php (configured in
 * naming-architecture.php).
 */
arch('src never imports Illuminate Foundation types')
    ->expect('Qiick\McpOAuth')
    ->not->toUse('Illuminate\Foundation');

arch('data transfer objects are readonly')
    ->expect('Qiick\McpOAuth\Data')
    ->classes()
    ->toBeReadonly();

arch('events are immutable')
    ->expect('Qiick\McpOAuth\Events')
    ->classes()
    ->toBeReadonly();

arch('test doubles shipped for apps start with Fake')
    ->expect('Qiick\McpOAuth\Testing')
    ->classes()
    ->toHavePrefix('Fake');
