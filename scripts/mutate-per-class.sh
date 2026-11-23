#!/usr/bin/env bash
# Enforce pest --mutate --min=95 on design §11.4 security-critical classes.
# One pest --mutate invocation per class (pcov). Never --covered-only, never
# || true, never method-level @pest-mutate-ignore. Empty list = scaffold no-op
# until feature classes land.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

CLASSES=(
  'Qiick\McpOAuth\Actions\ApproveConsentAction'
  'Qiick\McpOAuth\Actions\BindAccessTokenAction'
  'Qiick\McpOAuth\Actions\DenyConsentAction'
  'Qiick\McpOAuth\Actions\RecordConsentDecisionAction'
  'Qiick\McpOAuth\Bridge\FamilyRevokingRefreshTokenRepository'
  'Qiick\McpOAuth\ClientMetadataUriGuard'
  'Qiick\McpOAuth\ClientThrottleKey'
  'Qiick\McpOAuth\Http\Controllers\ApproveClientController'
  'Qiick\McpOAuth\Http\Controllers\AuthorizeClientController'
  'Qiick\McpOAuth\Http\Controllers\DenyClientController'
  'Qiick\McpOAuth\Http\Controllers\IssueTokenController'
  'Qiick\McpOAuth\Http\Controllers\RegisterClientController'
  'Qiick\McpOAuth\Http\Middleware\EnsureMcpOAuthEnabledMiddleware'
  'Qiick\McpOAuth\Http\Middleware\ValidateAuthorizationRequestMiddleware'
  'Qiick\McpOAuth\Http\Middleware\ValidateTokenRequestMiddleware'
  'Qiick\McpOAuth\Internal\PassportUserIdentifier'
  'Qiick\McpOAuth\McpOAuthReadiness'
  'Qiick\McpOAuth\McpOAuthRoutes'
  'Qiick\McpOAuth\McpOAuthServer'
  'Qiick\McpOAuth\RedirectUriGuard'
  'Qiick\McpOAuth\Services\AuthorizationResponseService'
  'Qiick\McpOAuth\Services\ConsentDecisionService'
  'Qiick\McpOAuth\Services\ConsentPageService'
  'Qiick\McpOAuth\Services\PendingAuthorizationRequestService'
  'Qiick\McpOAuth\Services\TokenErrorResponseService'
  'Qiick\McpOAuth\Views\InertiaConsentView'
)

MIN="${MUTATE_MIN:-95}"

if [[ "${#CLASSES[@]}" -eq 0 ]]; then
  echo "No mutation target classes yet (scaffold). Skipping."
  exit 0
fi

status=0

for class in "${CLASSES[@]}"; do
  echo "==> mutate ${class} (min=${MIN})"
  if ! vendor/bin/pest --mutate --min="${MIN}" --class="${class}"; then
    status=1
  fi
done

exit "${status}"
