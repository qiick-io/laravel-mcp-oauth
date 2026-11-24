#!/usr/bin/env bash
# Enforce pest --mutate --min=95 on design §11.4 security-critical classes.
# One pest --mutate invocation per class (pcov). Never --covered-only, never
# || true, never method-level @pest-mutate-ignore. Empty list = scaffold no-op
# until feature classes land.
#
# CI splits the list into parallel shards: MUTATE_SHARD=i MUTATE_SHARDS=n runs
# the classes at positions i, i+n, i+2n, … (1-based). Without them, every
# class runs, as locally.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# Not alphabetical on purpose: CI gives class i to shard i % MUTATE_SHARDS,
# and this order spreads the slow classes (RedirectUriGuard, McpOAuthRoutes,
# McpOAuthServer) so the five shards take about 11 to 16 minutes each
# (timings of CI run 45255766116). Append a new class at the end; when a
# shard passes 20 minutes, rebalance the order or add a shard.
CLASSES=(
  'Qiick\McpOAuth\RedirectUriGuard'
  'Qiick\McpOAuth\McpOAuthRoutes'
  'Qiick\McpOAuth\McpOAuthServer'
  'Qiick\McpOAuth\ClientThrottleKey'
  'Qiick\McpOAuth\Http\Middleware\ValidateTokenRequestMiddleware'
  'Qiick\McpOAuth\Services\PendingAuthorizationRequestService'
  'Qiick\McpOAuth\Actions\ApproveConsentAction'
  'Qiick\McpOAuth\Services\RevocationRequestService'
  'Qiick\McpOAuth\Services\AuthorizationResponseService'
  'Qiick\McpOAuth\ClientMetadataUriGuard'
  'Qiick\McpOAuth\Internal\ConsumedAuthCodeGrant'
  'Qiick\McpOAuth\Http\Controllers\AuthorizationServerMetadataController'
  'Qiick\McpOAuth\Actions\RevokeAuthCodeTokensAction'
  'Qiick\McpOAuth\Http\Controllers\RegisterClientController'
  'Qiick\McpOAuth\Bridge\FamilyRevokingRefreshTokenRepository'
  'Qiick\McpOAuth\McpOAuthReadiness'
  'Qiick\McpOAuth\Actions\RevokeTokenAction'
  'Qiick\McpOAuth\Actions\RecordConsentDecisionAction'
  'Qiick\McpOAuth\Services\ConsentDecisionService'
  'Qiick\McpOAuth\Actions\BindAccessTokenAction'
  'Qiick\McpOAuth\Views\InertiaConsentView'
  'Qiick\McpOAuth\Http\Controllers\DenyClientController'
  'Qiick\McpOAuth\Http\Middleware\ValidateAuthorizationRequestMiddleware'
  'Qiick\McpOAuth\Bridge\OneShotAuthCodeRepository'
  'Qiick\McpOAuth\Services\TokenErrorResponseService'
  'Qiick\McpOAuth\Actions\DenyConsentAction'
  'Qiick\McpOAuth\Http\Controllers\RevokeTokenController'
  'Qiick\McpOAuth\Internal\GrantBindingColumn'
  'Qiick\McpOAuth\Services\ConsentPageService'
  'Qiick\McpOAuth\Http\Middleware\EnsureMcpOAuthEnabledMiddleware'
  'Qiick\McpOAuth\Console\PruneAuthCodeExchangesCommand'
  'Qiick\McpOAuth\Actions\PruneAuthCodeExchangesAction'
  'Qiick\McpOAuth\Internal\PassportUserIdentifier'
  'Qiick\McpOAuth\Http\Controllers\ApproveClientController'
  'Qiick\McpOAuth\Http\Controllers\ProtectedResourceMetadataController'
  'Qiick\McpOAuth\Http\Controllers\AuthorizeClientController'
  'Qiick\McpOAuth\Http\Controllers\IssueTokenController'
)

MIN="${MUTATE_MIN:-95}"
SHARD="${MUTATE_SHARD:-1}"
SHARDS="${MUTATE_SHARDS:-1}"

if [[ "${#CLASSES[@]}" -eq 0 ]]; then
  echo "No mutation target classes yet (scaffold). Skipping."
  exit 0
fi

status=0

for index in "${!CLASSES[@]}"; do
  if (( index % SHARDS != SHARD - 1 )); then
    continue
  fi

  class="${CLASSES[$index]}"
  echo "==> mutate ${class} (min=${MIN}, shard ${SHARD}/${SHARDS})"
  if ! vendor/bin/pest --mutate --min="${MIN}" --class="${class}"; then
    status=1
  fi
done

exit "${status}"
