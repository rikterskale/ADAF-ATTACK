#!/usr/bin/env bash
# Install, upgrade, or uninstall ADAF-ATTACK on Kali in an isolated venv.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
extras="full"
install_system_deps=1
install_completion=1
package=""
manifest=""
sha256=""
python_command="python3"
venv_path="$repo_root/.venv"
uninstall=0
remove_workspace=0
json_output=0
workspace="${XDG_DATA_HOME:-$HOME/.local/share}/adaf-attack/workspaces"
ownership_marker="$venv_path/.adaf-attack-installer"

fail() {
  local code="$1" message="$2" remediation="$3"
  local suggested="${4:-adaf-attack doctor --profile user-readiness --explain}"
  if ((json_output)); then
    python3 - "$code" "$message" "$remediation" "$suggested" <<'PY'
import json
import sys
print(json.dumps({
    "ok": False,
    "error": {
        "code": sys.argv[1],
        "message": sys.argv[2],
        "remediation": sys.argv[3],
        "suggested_command": sys.argv[4],
        "recovery_command": "adaf-attack guide",
    },
}))
PY
  else
    printf 'Error [%s]: %s\nNext step: %s\nSuggested: %s\nWhen lost: adaf-attack guide\n' \
      "$code" "$message" "$remediation" "$suggested" >&2
  fi
  exit 1
}

usage() {
  cat <<'EOF'
Usage: bash scripts/install-kali.sh [options]

Options:
  --package PATH          Install a wheel or sdist instead of the source checkout
  --manifest PATH         release-manifest.json used to verify --package
  --sha256 HEX            Expected SHA-256 of --package
  --extras NAME           base, dev, tui, kerberos, reports, or full (default: full)
  --python COMMAND        Python command to use (default: python3)
  --venv PATH             Virtual environment path (default: repository .venv)
  --skip-system-deps      Do not run apt-get
  --skip-completion       Do not modify shell completion files
  --uninstall             Remove the installer venv; preserve workspaces
  --remove-workspace      With --uninstall, also delete workspace data
  --json                  Emit structured JSON errors
EOF
}

while (($#)); do
  case "$1" in
    --package) package="${2:?--package requires a path}"; shift 2 ;;
    --manifest) manifest="${2:?--manifest requires a path}"; shift 2 ;;
    --sha256) sha256="${2:?--sha256 requires a digest}"; shift 2 ;;
    --extras) extras="${2:?--extras requires a value}"; shift 2 ;;
    --python) python_command="${2:?--python requires a command}"; shift 2 ;;
    --venv)
      venv_path="${2:?--venv requires a path}"
      ownership_marker="$venv_path/.adaf-attack-installer"
      shift 2
      ;;
    --skip-system-deps) install_system_deps=0; shift ;;
    --skip-completion) install_completion=0; shift ;;
    --uninstall) uninstall=1; shift ;;
    --remove-workspace) remove_workspace=1; shift ;;
    --json) json_output=1; shift ;;
    --help|-h) usage; exit 0 ;;
    *) fail "INSTALLER_ARGUMENT" "Unknown option: $1" "Run bash scripts/install-kali.sh --help." ;;
  esac
done

case "$extras" in base|dev|tui|kerberos|reports|full) ;; *)
  fail "UNSUPPORTED_EXTRAS" "Unsupported extras: $extras" "Choose base, dev, tui, kerberos, reports, or full."
esac

# shellcheck disable=SC1091
if [[ "$(. /etc/os-release 2>/dev/null && printf '%s' "${ID:-}")" != "kali" ]]; then
  fail "KALI_REQUIRED" "This installer is intended for Kali Linux." "Use the generic Linux guide on another distribution."
fi

if ((uninstall)); then
  if [[ ! -f "$ownership_marker" ]] ||
    [[ "$(<"$ownership_marker")" != "ADAF_ATTACK_INSTALLER_V1" ]]; then
    fail "UNOWNED_VENV" "Refusing to remove unowned virtual environment: $venv_path" "Use the matching installer ownership marker or choose another --venv."
  fi
  canonical_venv="$(cd "$venv_path" && pwd -P)"
  case "$canonical_venv" in
    /|"$HOME"|"$repo_root")
      fail "UNSAFE_VENV" "Refusing unsafe virtual environment removal: $canonical_venv" "Choose a dedicated project virtual environment."
      ;;
  esac
  rm -rf -- "$canonical_venv"
  if ((remove_workspace)); then
    rm -rf -- "$workspace"
    echo "Removed workspace data: $workspace"
  else
    echo "Preserved workspace data: $workspace"
  fi
  echo "Uninstall complete."
  exit 0
fi

if ((remove_workspace)); then
  fail "INVALID_UNINSTALL_OPTION" "--remove-workspace is valid only with --uninstall." "Rerun with --uninstall or remove the option."
fi

if ((install_system_deps)); then
  apt=(apt-get)
  if ((EUID != 0)); then
    command -v sudo >/dev/null || {
      fail "SUDO_REQUIRED" "sudo is required for system packages." "Use --skip-system-deps if dependencies are already provisioned."
    }
    apt=(sudo apt-get)
  fi
  "${apt[@]}" update
  "${apt[@]}" install --yes \
    python3 python3-venv python3-pip python3-dev build-essential libkrb5-dev libssl-dev
fi

command -v "$python_command" >/dev/null || fail "PYTHON_NOT_FOUND" "Python command not found: $python_command" "Install Python 3.11-3.14 or pass --python." "python3 --version"
if ! "$python_command" -c 'import sys; raise SystemExit(0 if (3, 11) <= sys.version_info < (3, 15) else 1)'; then
  fail "PYTHON_UNSUPPORTED" "Python 3.11-3.14 is required." "Install a supported Python and pass --python." "adaf-attack doctor --profile user-readiness --explain"
fi

if [[ -e "$venv_path" && ! -f "$ownership_marker" ]]; then
  fail "INSTALLER_OWNERSHIP" "Refusing to modify unowned virtual environment: $venv_path" "Use the matching installer ownership marker or choose another --venv." "bash scripts/install-kali.sh --help"
fi
if [[ -f "$ownership_marker" ]] &&
  [[ "$(<"$ownership_marker")" != "ADAF_ATTACK_INSTALLER_V1" ]]; then
  fail "INSTALLER_OWNERSHIP" "Virtual environment ownership marker is invalid: $ownership_marker" "Recreate the venv with this installer or choose another --venv." "bash scripts/install-kali.sh --uninstall"
fi
if [[ -x "$venv_path/bin/python" ]]; then
  selected_base="$(
    "$python_command" -c 'import os, sys; print(os.path.realpath(sys.base_prefix))'
  )"
  existing_base="$(
    "$venv_path/bin/python" -c 'import os, sys; print(os.path.realpath(sys.base_prefix))'
  )"
  if [[ "$selected_base" != "$existing_base" ]]; then
    fail "VENV_REQUIRED" "Existing $venv_path uses $existing_base, not selected interpreter $selected_base." "Uninstall first or select the matching Python." "bash scripts/install-kali.sh --uninstall"
  fi
fi
if [[ ! -f "$ownership_marker" ]]; then
  mkdir -p -- "$venv_path"
  printf '%s\n' "ADAF_ATTACK_INSTALLER_V1" >"$ownership_marker"
fi
"$python_command" -m venv "$venv_path"
venv_python="$venv_path/bin/python"
"$venv_python" -m pip install --upgrade pip setuptools wheel

install_target="${package:-$repo_root}"
if [[ -n "$package" && ! -f "$package" ]]; then
  fail "INPUT_FILE_INVALID" "Package artifact does not exist: $package" "Pass an existing approved wheel path with --package." "ls -la \"$package\""
fi
if [[ -n "$package" ]]; then
  verify_args=( "$repo_root/scripts/verify_install_artifact.py" --artifact "$package" )
  if [[ -n "$manifest" ]]; then
    verify_args+=( --manifest "$manifest" )
  fi
  if [[ -n "$sha256" ]]; then
    verify_args+=( --sha256 "$sha256" )
  fi
  "$python_command" "${verify_args[@]}" || fail "INPUT_FILE_INVALID" "Package digest verification failed." "Place SHA256SUMS next to the wheel or pass --manifest / --sha256." "ls -la \"$(dirname "$package")\""
fi
if [[ "$extras" != "base" ]]; then
  install_target="${install_target}[${extras}]"
fi
"$venv_python" -m pip install --upgrade "$install_target"
"$venv_python" -m pip check

mkdir -p "$workspace"
if ((install_completion)); then
  shell_name="$(basename "${SHELL:-bash}")"
  if [[ "$shell_name" == "bash" || "$shell_name" == "zsh" ]]; then
    if "$venv_path/bin/adaf-attack" --install-completion "$shell_name"; then
      echo "Installed $shell_name completion for adaf-attack."
    else
      fail "INSTALLER_FAILURE" "Completion install failed for $shell_name." "Activate the venv and run adaf-attack --install-completion $shell_name manually." "source $venv_path/bin/activate"
    fi
  fi
fi

echo "Install complete. Activate with: source $venv_path/bin/activate"
echo "Verify with: adaf-attack doctor --profile user-readiness"
echo "Then run:    adaf-attack guide"
echo "Uninstall (workspace preserved): bash scripts/install-kali.sh --uninstall"
