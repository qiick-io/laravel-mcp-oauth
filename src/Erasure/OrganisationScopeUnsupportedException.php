<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Erasure;

use LogicException;

/**
 * MCP OAuth cannot distinguish one organisation's rows from another's.
 *
 * @api
 */
final class OrganisationScopeUnsupportedException extends LogicException
{
    public function __construct()
    {
        parent::__construct('MCP OAuth stores do not support organisation-scoped erasure.');
    }
}
