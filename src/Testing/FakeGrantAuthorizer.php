<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Testing;

use Illuminate\Http\Request;
use Qiick\McpOAuth\Contracts\GrantAuthorizer;
use Qiick\McpOAuth\Data\AuthorizationDecision;
use Qiick\McpOAuth\Data\GrantRecord;

/**
 * {@see GrantAuthorizer} that answers the decision it was given (allow by
 * default) and records the grants it was asked about.
 *
 * @api
 */
final class FakeGrantAuthorizer implements GrantAuthorizer
{
    /** @var list<GrantRecord> */
    public array $authorizedGrants = [];

    public AuthorizationDecision $decision;

    public function __construct(?AuthorizationDecision $decision = null)
    {
        $this->decision = $decision ?? AuthorizationDecision::allow();
    }

    public function authorize(Request $request, GrantRecord $grant): AuthorizationDecision
    {
        $this->authorizedGrants[] = $grant;

        return $this->decision;
    }
}
