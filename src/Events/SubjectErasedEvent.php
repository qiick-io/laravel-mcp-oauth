<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Events;

use Qiick\McpOAuth\Erasure\ErasureReport;

/**
 * Signals a committed MCP OAuth erasure using counts without subject identifiers.
 *
 * @api
 */
final readonly class SubjectErasedEvent
{
    public function __construct(public ErasureReport $report) {}
}
