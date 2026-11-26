<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Testing;

use Illuminate\Contracts\Auth\Authenticatable;
use Qiick\McpOAuth\Contracts\AuditLogger;
use Qiick\McpOAuth\Internal\PassportUserIdentifier;

/**
 * In-memory {@see AuditLogger} for package tests and product fakes: keeps
 * every entry, the causer as its user identifier.
 *
 * @api
 */
final class FakeAuditLogger implements AuditLogger
{
    /** @var list<array{event: string, causer: string|null, grantId: string|null, properties: array<string, scalar|list<scalar>|null>}> */
    public array $entries = [];

    public function record(string $event, ?Authenticatable $causer, ?string $grantId, array $properties): void
    {
        $this->entries[] = [
            'event' => $event,
            'causer' => $causer === null ? null : PassportUserIdentifier::of($causer),
            'grantId' => $grantId,
            'properties' => $properties,
        ];
    }
}
