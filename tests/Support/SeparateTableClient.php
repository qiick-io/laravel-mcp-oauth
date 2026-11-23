<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Tests\Support;

use Laravel\Passport\Client;

/**
 * A product client model stored outside `oauth_clients`
 * (`Passport::useClientModel()`), to prove the DCR cap counts the clients
 * Passport actually writes.
 */
final class SeparateTableClient extends Client
{
    protected $table = 'product_oauth_clients';
}
