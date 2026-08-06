#!/usr/bin/env bash
# Install ADAF-ATTACK on Kali Linux using an isolated virtual environment.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
extras="full"
install_system_deps=1

usage() {
  cat <<'EOF'
Usage: bash scripts/install-kali.sh [--extras dev|tui|kerberos|full] [--skip-system-deps]

Creates .venv in the repository and installs ADAF-ATTACK in editable mode.
EOF
}

while (($#)); do
  case "$1" in
    --extras)
      extras="${2:?--extras requires a value}"
      shift 2
      ;;
    --skip-system-deps)
      install_system_deps=0
      shift
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

case "$extras" in dev|tui|kerberos|full) ;; *) echo "Unsupported extras: $extras" >&2; exit 2 ;; esac

if [[ "$(. /etc/os-release 2>/dev/null && printf '%s' "${ID:-}")" != "kali" ]]; then
  echo "This installer is intended for Kali Linux; use your distribution's Python packages or pipx instead." >&2
  exit 1
fi

if ((install_system_deps)); then
  sudo apt-get update
  sudo apt-get install --yes python3 python3-venv python3-pip python3-dev build-essential libkrb5-dev libssl-dev
fi

command -v python3 >/dev/null || { echo "python3 is required." >&2; exit 1; }
python3 -m venv "$repo_root/.venv"
"$repo_root/.venv/bin/python" -m pip install --upgrade pip setuptools wheel
"$repo_root/.venv/bin/python" -m pip install --editable "$repo_root[$extras]"

echo "Install complete. Activate with: source $repo_root/.venv/bin/activate"
echo "Then verify with: adaf-attack doctor"
