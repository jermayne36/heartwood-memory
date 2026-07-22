#!/usr/bin/env bash
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel 2>/dev/null)" || {
  echo "error: run this script from a Heartwood Git checkout." >&2
  exit 1
}
hook_path="$repo_root/.git/hooks/pre-commit"

if [[ ! -d "$repo_root/.git/hooks" ]]; then
  echo "error: expected a .git/hooks directory in this checkout." >&2
  exit 1
fi

if [[ -e "$hook_path" ]] && ! grep -Fqx '# Heartwood local quality gate' "$hook_path"; then
  echo "error: refusing to overwrite an existing pre-commit hook: $hook_path" >&2
  exit 1
fi

printf '%s\n' '#!/usr/bin/env bash' '# Heartwood local quality gate' 'set -euo pipefail' 'repo_root="$(git rev-parse --show-toplevel)"' 'exec "$repo_root/scripts/check.sh"' >"$hook_path"
chmod +x "$hook_path"
printf 'Installed Heartwood quality gate at %s\n' "$hook_path"
