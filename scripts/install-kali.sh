#!/usr/bin/env bash
# Install, upgrade, or uninstall ADAF-ATTACK on Kali in an isolated venv.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
extras="full"
install_system_deps=1
install_completion=1
package=""
python_command="python3"
venv_path="$repo_root/.venv"
uninstall=0
remove_workspace=0
workspace="${XDG_DATA_HOME:-$HOME/.local/share}/adaf-attack/workspaces"
ownership_marker="$venv_path/.adaf-attack-installer"

usage() {
  cat <<'EOF'
Usage: bash scripts/install-kali.sh [options]

Options:
  --package PATH          Install a wheel or sdist instead of the source checkout
  --extras NAME           base, dev, tui, kerberos, reports, or full (default: full)
  --python COMMAND        Python command to use (default: python3)
  --venv PATH             Virtual environment path (default: repository .venv)
  --skip-system-deps      Do not run apt-get
  --skip-completion       Do not modify shell completion files
  --uninstall             Remove the installer venv; preserve workspaces
  --remove-workspace      With --uninstall, also delete workspace data
EOF
}

while (($#)); do
  case "$1" in
    --package) package="${2:?--package requires a path}"; shift 2 ;;
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
    --help|-h) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

case "$extras" in base|dev|tui|kerberos|reports|full) ;; *)
  echo "Unsupported extras: $extras" >&2
  exit 2
esac

# shellcheck disable=SC1091
if [[ "$(. /etc/os-release 2>/dev/null && printf '%s' "${ID:-}")" != "kali" ]]; then
  echo "This installer is intended for Kali Linux; use the generic Linux guide instead." >&2
  exit 1
fi

if ((uninstall)); then
  if [[ ! -f "$ownership_marker" ]] ||
    [[ "$(<"$ownership_marker")" != "ADAF_ATTACK_INSTALLER_V1" ]]; then
    echo "Refusing to remove unowned virtual environment: $venv_path" >&2
    exit 1
  fi
  canonical_venv="$(cd "$venv_path" && pwd -P)"
  case "$canonical_venv" in
    /|"$HOME"|"$repo_root")
      echo "Refusing unsafe virtual environment removal: $canonical_venv" >&2
      exit 1
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
  echo "--remove-workspace is valid only with --uninstall." >&2
  exit 2
fi

if ((install_system_deps)); then
  apt=(apt-get)
  if ((EUID != 0)); then
    command -v sudo >/dev/null || {
      echo "sudo is required for system packages; use --skip-system-deps if already provisioned." >&2
      exit 1
    }
    apt=(sudo apt-get)
  fi
  "${apt[@]}" update
  "${apt[@]}" install --yes \
    python3 python3-venv python3-pip python3-dev build-essential libkrb5-dev libssl-dev
fi

command -v "$python_command" >/dev/null || {
  echo "Python command not found: $python_command" >&2
  exit 1
}
"$python_command" -c \
  'import sys; assert (3, 11) <= sys.version_info < (3, 14), f"Python 3.11-3.13 required, found {sys.version.split()[0]}"'

if [[ -e "$venv_path" && ! -f "$ownership_marker" ]]; then
  echo "Refusing to modify unowned virtual environment: $venv_path" >&2
  exit 1
fi
if [[ -f "$ownership_marker" ]] &&
  [[ "$(<"$ownership_marker")" != "ADAF_ATTACK_INSTALLER_V1" ]]; then
  echo "Virtual environment ownership marker is invalid: $ownership_marker" >&2
  exit 1
fi
if [[ -x "$venv_path/bin/python" ]]; then
  selected_base="$(
    "$python_command" -c 'import os, sys; print(os.path.realpath(sys.base_prefix))'
  )"
  existing_base="$(
    "$venv_path/bin/python" -c 'import os, sys; print(os.path.realpath(sys.base_prefix))'
  )"
  if [[ "$selected_base" != "$existing_base" ]]; then
    echo "Existing $venv_path uses $existing_base, not selected interpreter $selected_base." >&2
    echo "Uninstall first or select the matching Python." >&2
    exit 1
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
  echo "Package artifact does not exist: $package" >&2
  exit 1
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
      echo "Completion install failed; run 'adaf-attack --install-completion $shell_name' manually." >&2
      exit 1
    fi
  fi
fi

echo "Install complete. Activate with: source $venv_path/bin/activate"
echo "Verify with: adaf-attack doctor --explain"
echo "Uninstall (workspace preserved): bash scripts/install-kali.sh --uninstall"
