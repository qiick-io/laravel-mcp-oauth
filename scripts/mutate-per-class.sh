#!/usr/bin/env bash
# Enforce pest --mutate --min=95 on design §11.4 security-critical classes.
# One pest --mutate invocation per class (pcov). Never --covered-only, never
# || true, never method-level @pest-mutate-ignore.
#
# MUTATE_SCOPE (from the shared package matrix, app-ui docs/package-matrix.md):
# - `all` (push, nightly, manual, and locally by default): every class below;
# - `changed` (a pull request): only those of MUTATE_CLASSES, the JSON array
#   of src/ paths the PR changed, that are in the lists below. A changed class
#   outside them is reported and skipped: the gate is this curated list.
#
# CI splits the work into parallel shards with MUTATE_SHARD=i MUTATE_SHARDS=n
# (see the selection below). Without them, every selected class runs.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# The slowest classes (12 to 13 minutes each in CI) get a shard each; the
# rest are dealt round-robin over the other shards. A new class goes in
# CLASSES; move it to DEDICATED_CLASSES (and add a shard) only if it is that slow.
DEDICATED_CLASSES=(
  'Qiick\McpOAuth\RedirectUriGuard'
  'Qiick\McpOAuth\McpOAuthServer'
  'Qiick\McpOAuth\McpOAuthRoutes'
  'Qiick\McpOAuth\McpOAuthServiceProvider'
)

CLASSES=(
  'Qiick\McpOAuth\AccessTokenAuthenticator'
  'Qiick\McpOAuth\Actions\ApproveConsentAction'
  'Qiick\McpOAuth\Actions\BindAccessTokenAction'
  'Qiick\McpOAuth\Actions\BlockClientAction'
  'Qiick\McpOAuth\Actions\BlockRedirectHostAction'
  'Qiick\McpOAuth\Actions\BulkBlockClientsAction'
  'Qiick\McpOAuth\Actions\DeleteClientAction'
  'Qiick\McpOAuth\Actions\DenyConsentAction'
  'Qiick\McpOAuth\Actions\PruneAuthCodeExchangesAction'
  'Qiick\McpOAuth\Actions\PruneUnusedClientsAction'
  'Qiick\McpOAuth\Actions\PurgeRevokedRecordsAction'
  'Qiick\McpOAuth\Actions\RecordConsentDecisionAction'
  'Qiick\McpOAuth\Actions\RevokeAuthCodeTokensAction'
  'Qiick\McpOAuth\Actions\RevokeConnectedAppAction'
  'Qiick\McpOAuth\Actions\RevokeGrantTokensAction'
  'Qiick\McpOAuth\Actions\RevokeTokenAction'
  'Qiick\McpOAuth\Actions\SwitchMcpOAuthAction'
  'Qiick\McpOAuth\Actions\UnblockRedirectHostAction'
  'Qiick\McpOAuth\Bridge\FamilyRevokingRefreshTokenRepository'
  'Qiick\McpOAuth\Bridge\OneShotAuthCodeRepository'
  'Qiick\McpOAuth\ClientMetadataUriGuard'
  'Qiick\McpOAuth\ClientThrottleKey'
  'Qiick\McpOAuth\Console\McpOAuthCheckCommand'
  'Qiick\McpOAuth\Console\PruneAuthCodeExchangesCommand'
  'Qiick\McpOAuth\Console\PruneUnusedClientsCommand'
  'Qiick\McpOAuth\Console\PurgeRevokedRecordsCommand'
  'Qiick\McpOAuth\Http\Controllers\ApproveClientController'
  'Qiick\McpOAuth\Http\Controllers\AuthorizeClientController'
  'Qiick\McpOAuth\Http\Controllers\ClientAdminController'
  'Qiick\McpOAuth\Http\Controllers\ConnectedAppsController'
  'Qiick\McpOAuth\Http\Controllers\DenyClientController'
  'Qiick\McpOAuth\Http\Controllers\IssueTokenController'
  'Qiick\McpOAuth\Http\Controllers\PruneUnusedClientsController'
  'Qiick\McpOAuth\Http\Controllers\RegisterClientController'
  'Qiick\McpOAuth\Http\Controllers\RevokeTokenController'
  'Qiick\McpOAuth\Http\Middleware\EnsureMcpOAuthEnabledMiddleware'
  'Qiick\McpOAuth\Http\Middleware\McpBearerDoorMiddleware'
  'Qiick\McpOAuth\Http\Middleware\McpChallengeMiddleware'
  'Qiick\McpOAuth\Http\Middleware\ValidateAuthorizationRequestMiddleware'
  'Qiick\McpOAuth\Http\Middleware\ValidateTokenRequestMiddleware'
  'Qiick\McpOAuth\Internal\ConsumedAuthCodeGrant'
  'Qiick\McpOAuth\Internal\GrantBindingColumn'
  'Qiick\McpOAuth\Internal\PassportUserIdentifier'
  'Qiick\McpOAuth\McpOAuthAdminRoutes'
  'Qiick\McpOAuth\McpOAuthReadiness'
  'Qiick\McpOAuth\McpOAuthSettingsRoutes'
  'Qiick\McpOAuth\Services\AuthorizationResponseService'
  'Qiick\McpOAuth\Services\ClientAdminService'
  'Qiick\McpOAuth\Services\ConnectedAppsService'
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

SCOPE="${MUTATE_SCOPE:-all}"

if [[ "${SCOPE}" == changed ]]; then
  # The PR's changed paths as class names (src/Foo/Bar.php -> Qiick\McpOAuth\Foo\Bar);
  # a deleted path is not mutated.
  # Captured first: a failing node (a malformed list) stops the script under set -e.
  changed_class_names="$(node -e '
    const fs = require("node:fs");
    const files = JSON.parse(process.env.MUTATE_CLASSES ?? "[]");
    if (!Array.isArray(files) || files.some((file) => typeof file !== "string" || !/^src\/(?!Testing\/)[\w/]+\.php$/.test(file))) {
      throw new Error("MUTATE_CLASSES must be an array of package source paths");
    }
    for (const file of files) {
      if (fs.existsSync(file)) {
        console.log("Qiick\\McpOAuth\\" + file.slice(4, -4).replaceAll("/", "\\"));
      }
    }
  ')"
  CHANGED_CLASSES=()

  if [[ -n "${changed_class_names}" ]]; then
    mapfile -t CHANGED_CLASSES <<< "${changed_class_names}"
  fi

  CURATED_CLASSES=("${DEDICATED_CLASSES[@]}" "${CLASSES[@]}")
  GATED_CLASSES=()

  for changed_class in "${CHANGED_CLASSES[@]}"; do
    if [[ " ${CURATED_CLASSES[*]} " == *" ${changed_class} "* ]]; then
      GATED_CLASSES+=("${changed_class}")
    elif (( SHARD == 1 )); then
      echo "Not in the mutation gate, skipped: ${changed_class}"
    fi
  done

  SELECTED_CLASSES=()

  for index in "${!GATED_CLASSES[@]}"; do
    if (( index % SHARDS == SHARD - 1 )); then
      SELECTED_CLASSES+=("${GATED_CLASSES[$index]}")
    fi
  done

  # A pull request may change no gated class, or fewer than there are shards.
  if (( ${#SELECTED_CLASSES[@]} == 0 )); then
    echo "Shard ${SHARD}/${SHARDS}: no changed class to mutate."
    exit 0
  fi
elif [[ "${SCOPE}" != all ]]; then
  echo "MUTATE_SCOPE must be all or changed." >&2
  exit 1
elif (( SHARDS == 1 )); then
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
