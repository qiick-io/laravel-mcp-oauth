<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Testing;

use Closure;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Request;
use Qiick\McpOAuth\Contracts\ConsentProvider;
use Qiick\McpOAuth\Data\ClientInfo;
use Qiick\McpOAuth\Data\ConsentDecision;
use Qiick\McpOAuth\Data\ConsentOptions;

/**
 * {@see ConsentProvider} with fixed options for package tests and product
 * fakes. Records every client it was asked about and every decision it
 * validated; an optional rejector closure plays the product's own refusal.
 *
 * @api
 */
final class FakeConsentProvider implements ConsentProvider
{
    /** @var list<ClientInfo> */
    public array $askedClients = [];

    /** @var list<ConsentDecision> */
    public array $validatedDecisions = [];

    /**
     * @param  (Closure(ConsentDecision): void)|null  $rejectDecision  throws to refuse
     */
    public function __construct(
        private readonly ConsentOptions $consentOptions,
        private readonly ?Closure $rejectDecision = null,
    ) {}

    public function options(Request $request, Authenticatable $user, ClientInfo $client): ConsentOptions
    {
        $this->askedClients[] = $client;

        return $this->consentOptions;
    }

    public function validate(Request $request, Authenticatable $user, ConsentDecision $decision): void
    {
        $this->validatedDecisions[] = $decision;

        if ($this->rejectDecision !== null) {
            ($this->rejectDecision)($decision);
        }
    }
}
