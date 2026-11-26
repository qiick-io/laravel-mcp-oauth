<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;

/**
 * Audit sink. Ids and hosts only; never token material.
 *
 * Failure semantics (Codex review of #60): the package calls record() inside
 * the database transaction of the change it describes, on the connection
 * that change writes (Passport's for grants, tokens and clients, the
 * package's for blocked hosts and consent evidence), and before the change's
 * event is dispatched. So:
 *
 * - a sink that writes on that connection commits or rolls back with the
 *   change, exactly once;
 * - a sink that throws rolls the change back, no event is dispatched, and
 *   the exception reaches the caller: no change is committed without its
 *   entry, and a retry starts from the state before it;
 * - a sink on another connection or outside the database (a queue, a log
 *   file) keeps an entry written before a later rollback; it should defer
 *   its write to the commit when that matters.
 *
 * The admin switch writes the product's store through a closure; its entry
 * is recorded before that closure runs, in a transaction on the default
 * connection, so a failing sink leaves the store untouched.
 *
 * docs/audit.md maps each entry onto the 1.5 activity log names.
 *
 * @api
 */
interface AuditLogger
{
    /**
     * @param  array<string, scalar|list<scalar>|null>  $properties
     */
    public function record(string $event, ?Authenticatable $causer, ?string $grantId, array $properties): void;
}
