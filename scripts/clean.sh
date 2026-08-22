#!/usr/bin/env bash
# Remove local build byproducts. Never touches tracked files, workspaces, or venvs.
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$repo_root"

targets=(
  ".coverage"
  ".coverage.*"
  "coverage.xml"
  "htmlcov"
  ".mypy_cache"
  ".ruff_cache"
  ".pytest_cache"
  "build"
  "dist"
)

removed=0
for pattern in "${targets[@]}"; do
  for path in $pattern; do
    if [[ -e "$path" ]]; then
      rm -rf -- "$path"
      echo "removed: $path"
      removed=$((removed + 1))
    fi
  done
done

# egg-info in src/ and top-level
find . -maxdepth 3 -type d -name '*.egg-info' -not -path './.venv*/*' -print -exec rm -rf {} + 2>/dev/null || true

# __pycache__ everywhere except venvs
find . -type d -name '__pycache__' -not -path './.venv*/*' -not -path './node_modules/*' -print -exec rm -rf {} + 2>/dev/null || true

echo "clean: ${removed} top-level target(s) removed"
