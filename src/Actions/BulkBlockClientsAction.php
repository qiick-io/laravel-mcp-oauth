<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Actions;

use Illuminate\Contracts\Auth\Authenticatable;
use Laravel\Passport\Client;
use Qiick\McpOAuth\Services\ClientAdminService;

/**
 * Blocks several clients at once (design §5.2, S40). Each is blocked in full
 * by {@see BlockClientAction}, one transaction per client; an id that names
 * no package client (the product's own Passport clients included), or a
 * client already revoked, is skipped. The request caps the
 * list at 100 distinct ids.
 */
final class BulkBlockClientsAction
{
    public function __construct(
        private readonly BlockClientAction $blockClientAction,
    ) {}

    /**
     * @param  list<string>  $clientIds
     */
    public function execute(array $clientIds, ?Authenticatable $actor): void
    {
        /** @var iterable<Client> $clients */
        $clients = ClientAdminService::packageClients()->whereKey($clientIds)->where('revoked', false)->get();

        foreach ($clients as $client) {
            $this->blockClientAction->execute($client, $actor);
        }
    }
}
