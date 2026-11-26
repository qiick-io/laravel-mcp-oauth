<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Actions;

use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Http\Request;
use Qiick\McpOAuth\Data\ConsentDecision;
use Qiick\McpOAuth\Data\GrantRecord;
use Qiick\McpOAuth\Data\PendingAuthorizationRequestData;
use Qiick\McpOAuth\Internal\BoundedPositiveInt;
use Qiick\McpOAuth\Internal\PassportUserIdentifier;
use Qiick\McpOAuth\Models\OAuthConsentRecord;
use Qiick\McpOAuth\RedirectUriGuard;

/**
 * Writes one append-only `oauth_consent_records` row per consent decision,
 * approved or denied (standards review S4, decision 5: a denial leaves
 * evidence too). An approval keeps `retention_until` null while its grant is
 * active; a denial is kept `revoked_retention_days` (90) from now.
 * The IP address and user agent are personal data, purged with the row.
 *
 * @internal
 */
final class RecordConsentDecisionAction
{
    public function __construct(
        private readonly RedirectUriGuard $redirectUriGuard,
        private readonly ConfigRepository $config,
    ) {}

    /**
     * @param  ConsentDecision|null  $decision  null for a denial
     * @param  GrantRecord|null  $grant  the new grant of an approval
     */
    public function execute(
        Request $request,
        PendingAuthorizationRequestData $pendingAuthorizationRequest,
        string $redirectUri,
        ?ConsentDecision $decision,
        ?GrantRecord $grant,
    ): OAuthConsentRecord {
        $authorizationRequest = $pendingAuthorizationRequest->authorizationRequest;
        $isDenied = $decision === null;
        $userAgent = $request->userAgent();

        return OAuthConsentRecord::query()->create([
            'client_id' => $authorizationRequest->getClient()->getIdentifier(),
            'user_identifier' => PassportUserIdentifier::of($pendingAuthorizationRequest->user),
            'grant_id' => $grant?->id,
            'decision' => $isDenied ? 'denied' : 'approved',
            'redirect_uri' => $redirectUri,
            'redirect_host' => $this->redirectUriGuard->displayHostOf($redirectUri),
            'resource' => $pendingAuthorizationRequest->renderedResource,
            // League scope entities JSON-serialise to their identifier.
            'requested_scopes' => $authorizationRequest->getScopes(),
            'granted_scopes' => $decision?->scopes,
            'role' => $decision?->role,
            'resources' => $decision?->resources,
            'all_resources' => $decision !== null && $decision->allResources,
            'attributes' => $decision?->attributes,
            // What the rendered page showed, for an approval and a denial alike.
            'consent_version' => $pendingAuthorizationRequest->renderedConsentVersion,
            'locale' => $pendingAuthorizationRequest->renderedLocale,
            'ip_address' => $request->ip(),
            'user_agent' => $userAgent === null ? null : mb_strcut($userAgent, 0, 512),
            'retention_until' => $isDenied
                ? now()->addDays(BoundedPositiveInt::require(
                    $this->config->get('mcp-oauth.revoked_retention_days'),
                    'revoked_retention_days',
                    BoundedPositiveInt::REVOKED_RETENTION_DAYS_MAX,
                ))
                : null,
        ]);
    }
}
