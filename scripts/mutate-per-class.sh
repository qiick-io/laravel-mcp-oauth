#!/usr/bin/env bash
# Enforce pest --mutate --min=95 on design §11.4 security-critical classes.
# One pest --mutate invocation per class (pcov). Never --covered-only, never
# || true, never method-level @pest-mutate-ignore. Empty list = scaffold no-op
# until feature classes land.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

CLASSES=(
  # McpOAuthServer and RedirectUriGuard land here once their suites hit ≥95% MSI.
  'Qiick\McpOAuth\ClientThrottleKey'
  'Qiick\McpOAuth\McpOAuthReadiness'
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
