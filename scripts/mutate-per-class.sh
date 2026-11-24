#!/usr/bin/env bash
# Enforce pest --mutate --min=95 on design §11.4 security-critical classes.
# One pest --mutate invocation per class (pcov). Never --covered-only, never
# || true, never method-level @pest-mutate-ignore. Empty list = scaffold no-op
# until feature classes land.
#
# CI splits the work into parallel shards with MUTATE_SHARD=i MUTATE_SHARDS=n
# (see the selection below). Without them, every class runs, as locally.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# The slowest classes (12 to 13 minutes each in CI) get a shard each; the
# rest are dealt round-robin over the other shards. A new class goes in
# CLASSES; move it to DEDICATED_CLASSES (and add a shard) only if it is that slow.
DEDICATED_CLASSES=(
  'Qiick\McpOAuth\AccessTokenAuthenticator'
  'Qiick\McpOAuth\Http\Middleware\McpBearerDoorMiddleware'
  'Qiick\McpOAuth\Http\Middleware\McpChallengeMiddleware'
  'Qiick\McpOAuth\McpOAuthRoutes'
  'Qiick\McpOAuth\McpOAuthServer'
  'Qiick\McpOAuth\RedirectUriGuard'
)

CLASSES=(
  'Qiick\McpOAuth\Actions\ApproveConsentAction'
  'Qiick\McpOAuth\Actions\BindAccessTokenAction'
  'Qiick\McpOAuth\Actions\DenyConsentAction'
  'Qiick\McpOAuth\Actions\PruneAuthCodeExchangesAction'
  'Qiick\McpOAuth\Actions\RecordConsentDecisionAction'
  'Qiick\McpOAuth\Actions\RevokeAuthCodeTokensAction'
  'Qiick\McpOAuth\Actions\RevokeTokenAction'
  'Qiick\McpOAuth\Bridge\FamilyRevokingRefreshTokenRepository'
  'Qiick\McpOAuth\Bridge\OneShotAuthCodeRepository'
  'Qiick\McpOAuth\ClientMetadataUriGuard'
  'Qiick\McpOAuth\ClientThrottleKey'
  'Qiick\McpOAuth\Console\PruneAuthCodeExchangesCommand'
  'Qiick\McpOAuth\Http\Controllers\ApproveClientController'
  'Qiick\McpOAuth\Http\Controllers\AuthorizationServerMetadataController'
  'Qiick\McpOAuth\Http\Controllers\AuthorizeClientController'
  'Qiick\McpOAuth\Http\Controllers\DenyClientController'
  'Qiick\McpOAuth\Http\Controllers\IssueTokenController'
  'Qiick\McpOAuth\Http\Controllers\ProtectedResourceMetadataController'
  'Qiick\McpOAuth\Http\Controllers\RegisterClientController'
  'Qiick\McpOAuth\Http\Controllers\RevokeTokenController'
  'Qiick\McpOAuth\Http\Middleware\EnsureMcpOAuthEnabledMiddleware'
  'Qiick\McpOAuth\Http\Middleware\ValidateAuthorizationRequestMiddleware'
  'Qiick\McpOAuth\Http\Middleware\ValidateTokenRequestMiddleware'
  'Qiick\McpOAuth\Internal\ConsumedAuthCodeGrant'
  'Qiick\McpOAuth\Internal\GrantBindingColumn'
  'Qiick\McpOAuth\Internal\PassportUserIdentifier'
  'Qiick\McpOAuth\McpOAuthReadiness'
  'Qiick\McpOAuth\Services\AuthorizationResponseService'
  'Qiick\McpOAuth\Services\ConsentDecisionService'
  'Qiick\McpOAuth\Services\ConsentPageService'
  'Qiick\McpOAuth\Services\PendingAuthorizationRequestService'
  'Qiick\McpOAuth\Services\RevocationRequestService'
  'Qiick\McpOAuth\Services\TokenErrorResponseService'
  'Qiick\McpOAuth\Views\InertiaConsentView'
)

MIN="${MUTATE_MIN:-95}"
SHARD="${MUTATE_SHARD:-1}"
SHARDS="${MUTATE_SHARDS:-1}"

DEDICATED_COUNT="${#DEDICATED_CLASSES[@]}"

# Locally (one shard) every class runs; in CI, shards 1..DEDICATED_COUNT take
# one dedicated class each and the other shards share CLASSES.
if (( SHARD < 1 || SHARD > SHARDS )); then
  echo "MUTATE_SHARD must be between 1 and MUTATE_SHARDS (${SHARDS})." >&2
  exit 1
fi

if (( SHARDS == 1 )); then
  SELECTED_CLASSES=("${DEDICATED_CLASSES[@]}" "${CLASSES[@]}")
elif (( SHARDS <= DEDICATED_COUNT )); then
  echo "MUTATE_SHARDS must exceed the ${DEDICATED_COUNT} dedicated classes." >&2
  exit 1
elif (( SHARD <= DEDICATED_COUNT )); then
  SELECTED_CLASSES=("${DEDICATED_CLASSES[SHARD - 1]}")
else
  SHARED_SHARDS=$(( SHARDS - DEDICATED_COUNT ))
  SELECTED_CLASSES=()

  for index in "${!CLASSES[@]}"; do
    if (( index % SHARED_SHARDS == SHARD - DEDICATED_COUNT - 1 )); then
      SELECTED_CLASSES+=("${CLASSES[$index]}")
    fi
  done
fi

# A shard that mutates nothing would pass green; it means a misconfiguration.
if (( ${#SELECTED_CLASSES[@]} == 0 )); then
  echo "Shard ${SHARD}/${SHARDS} selected no class to mutate." >&2
  exit 1
fi

status=0

for class in "${SELECTED_CLASSES[@]}"; do
  echo "==> mutate ${class} (min=${MIN}, shard ${SHARD}/${SHARDS})"
  if ! vendor/bin/pest --mutate --min="${MIN}" --class="${class}"; then
    status=1
  fi
done

exit "${status}"
