#!/usr/bin/env bash
# Score each executable PHP source type in its own Pest run. Exact paths keep
# similarly named types separate and let Pest include traits and enum methods.
set -euo pipefail

# Empty arrays under set -u need Bash 4.4 or later.
if (( BASH_VERSINFO[0] < 4 || (BASH_VERSINFO[0] == 4 && BASH_VERSINFO[1] < 4) )); then
  echo "scripts/mutate-per-class.sh requires Bash 4.4 or later." >&2
  exit 1
fi

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

MIN="${MUTATE_MIN:-95}"
SCOPE="${MUTATE_SCOPE:-all}"

if [[ -v MUTATE_SHARD && ! -v MUTATE_SHARDS ]] || [[ -v MUTATE_SHARDS && ! -v MUTATE_SHARD ]]; then
  echo "Set both MUTATE_SHARD and MUTATE_SHARDS to run a shard." >&2
  exit 1
fi

SHARD="${MUTATE_SHARD-1}"
SHARDS="${MUTATE_SHARDS-1}"

for shard_input in "${SHARD}" "${SHARDS}"; do
  if [[ ! "${shard_input}" =~ ^[1-9][0-9]*$ ]]; then
    echo "MUTATE_SHARD and MUTATE_SHARDS must be positive integers." >&2
    exit 1
  fi
done

if (( SHARD > SHARDS )); then
  echo "MUTATE_SHARD must be between 1 and MUTATE_SHARDS (${SHARDS})." >&2
  exit 1
fi

CHANGED_FILES=""
case "${SCOPE}" in
  changed)
    CHANGED_FILES="$(node -e '
      const paths = JSON.parse(process.env.MUTATE_CLASSES);
      if (!Array.isArray(paths) || paths.some((path) => typeof path !== "string" || !/^src\/(?:\w+\/)*\w+\.php$/.test(path))) {
        throw new Error("MUTATE_CLASSES must be an array of package source paths.");
      }
      console.log(paths.join("\n"));
    ')"
    ;;
  all) ;;
  *)
    echo "MUTATE_SCOPE must be all or changed." >&2
    exit 1
    ;;
esac

# Long-running classes keep their dedicated jobs. Other full-run paths are
# distributed in stable order over the remaining shards.
DEDICATED_FILES=(
  src/RedirectUriGuard.php
  src/McpOAuthServer.php
  src/McpOAuthRoutes.php
  src/McpOAuthServiceProvider.php
  src/Services/ClientMetadataRegistryService.php
)
DEDICATED_COUNT="${#DEDICATED_FILES[@]}"

if [[ "${SCOPE}" == all ]] && (( SHARDS > 1 && SHARDS <= DEDICATED_COUNT )); then
  echo "MUTATE_SHARDS must exceed the ${DEDICATED_COUNT} dedicated jobs." >&2
  exit 1
fi

FILES=()
while IFS= read -r file; do
  declaration="$(grep -m1 -E '^(final |abstract )?(readonly )?(class|interface|enum|trait) ' "${file}" || true)"

  case "${declaration}" in
    "") echo "Unclassified source file: ${file}" >&2; exit 1 ;;
    *interface\ *) continue ;;
  esac

  if [[ "${SCOPE}" == changed ]] && ! grep -Fxq -- "${file}" <<< "${CHANGED_FILES}"; then
    continue
  fi

  if [[ "${SCOPE}" == all ]] && (( SHARDS > 1 )); then
    if [[ " ${DEDICATED_FILES[*]} " == *" ${file} "* ]]; then
      continue
    fi
  fi

  FILES+=("${file}")
done < <(find src -type f -name '*.php' | LC_ALL=C sort)

SELECTED=()
if (( SHARDS == 1 )); then
  SELECTED=("${FILES[@]}")
elif [[ "${SCOPE}" == all ]] && (( SHARD <= DEDICATED_COUNT )); then
  SELECTED=("${DEDICATED_FILES[SHARD - 1]}")
  if [[ ! -f "${SELECTED[0]}" ]]; then
    echo "Missing dedicated mutation path: ${SELECTED[0]}" >&2
    exit 1
  fi
else
  offset=0
  if [[ "${SCOPE}" == all ]]; then
    offset="${DEDICATED_COUNT}"
  fi

  for index in "${!FILES[@]}"; do
    if (( index % (SHARDS - offset) == SHARD - offset - 1 )); then
      SELECTED+=("${FILES[index]}")
    fi
  done
fi

if (( ${#SELECTED[@]} == 0 )); then
  if [[ "${SCOPE}" == changed ]]; then
    echo "Shard ${SHARD}/${SHARDS}: no changed executable source."
    exit 0
  fi

  echo "Shard ${SHARD}/${SHARDS} selected no executable source." >&2
  exit 1
fi

if [[ "${MUTATE_LIST:-}" == 1 ]]; then
  printf '%s\n' "${SELECTED[@]}"
  exit 0
fi

status=0
for file in "${SELECTED[@]}"; do
  echo "==> mutate ${file} (min=${MIN}, shard ${SHARD}/${SHARDS})"
  # Marker classes, constructor-only DTOs and case-only enums can have zero mutants.
  if ! vendor/bin/pest --mutate --min="${MIN}" --path="${file}" --ignore-min-score-on-zero-mutations; then
    status=1
  fi
done

exit "${status}"
