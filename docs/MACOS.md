# macOS installation and lifecycle

ADAF-ATTACK supports Python 3.11-3.14 on macOS. Hosted CI installs the built
wheel on macOS 14/Python 3.13 and exercises the public offline CLI. Source tests
also cover Python 3.14 on macOS; the focused artifact wheel path remains tested
through Python 3.13.

## Prerequisites

Install a supported Python from python.org or Homebrew and confirm it is not the
system Python:

```bash
python3 --version
command -v python3
```

## Install a release wheel

Download the approved wheel from the private GitHub release:

```bash
mkdir -p "$HOME/.venvs"
python3 -m venv "$HOME/.venvs/adaf-attack"
source "$HOME/.venvs/adaf-attack/bin/activate"
python -m pip install --upgrade pip
python -m pip install "$HOME/Downloads/adaf_attack-0.10.1-py3-none-any.whl[full]"
python -m pip check
```

## Verify and first safe offline run

```bash
adaf-attack --version
adaf-attack --format json doctor --profile user-readiness --explain
adaf-attack quickstart --workspace ./quickstart
adaf-attack guide --workspace ./quickstart --session ./quickstart/demo-session
adaf-attack list-capabilities
adaf-attack paths
```

These checks do not contact a target. Session evidence defaults below the macOS
user data directory reported by `paths`. When lost, run `adaf-attack guide`.

## Upgrade, downgrade, and uninstall

Install an explicitly approved newer or older wheel in the same venv:

```bash
python -m pip install --upgrade "$HOME/Downloads/adaf_attack-0.10.1-py3-none-any.whl[full]"
adaf-attack --version
```

Uninstall by removing the dedicated venv. This preserves workspaces:

```bash
deactivate
rm -rf "$HOME/.venvs/adaf-attack"
```

Delete workspace data only after confirming the path with `adaf-attack paths`
and completing evidence-retention requirements.

## Troubleshooting and support boundary

If command discovery, certificates, a proxy, or an offline install fails, use
[TROUBLESHOOTING.md](TROUBLESHOOTING.md). Hosted CI does not prove Homebrew
policy, endpoint controls, native Kerberos configuration, or live AD behavior.
