<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Request;
use Laravel\Passport\Client;
use Laravel\Passport\Scope;
use Qiick\McpOAuth\Data\ConsentPage;
use Symfony\Component\HttpFoundation\Response;

/**
 * Renders the consent page from Passport's authorization view parameters.
 *
 * @api
 */
interface ConsentView
{
    /**
     * @param  array{
     *     request: Request,
     *     user: Authenticatable,
     *     client: Client,
     *     scopes: list<Scope>,
     *     authToken: string
     * }  $parameters
     */
    public function render(array $parameters, ConsentPage $page): Response;
}
