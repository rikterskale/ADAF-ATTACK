# Kali Linux support

ADAF-ATTACK supports Kali Linux with Python 3.11 or newer. It uses the standard
XDG data locations, so session artifacts default to
`~/.local/share/adaf-attack/workspaces`.

## Install

Clone the repository, then run the installer from the repository root:

```bash
bash scripts/install-kali.sh
source .venv/bin/activate
adaf-attack doctor
```

The installer installs the build and Python prerequisites through `apt`, then
creates a project-local `.venv` and installs the `full` extra set. To use
already-provisioned packages, omit the `apt` step:

```bash
bash scripts/install-kali.sh --skip-system-deps
```

Select a smaller dependency set with `--extras dev`, `--extras tui`, or
`--extras kerberos`.

## Verify

```bash
adaf-attack --version
adaf-attack doctor --explain
adaf-attack paths
```

`doctor` reports `Kali Linux` when `/etc/os-release` identifies the host as
Kali. You can override the artifact location without changing the installer:

```bash
export ADAF_ATTACK_WORKSPACE="$HOME/adaf-workspaces"
```

## Notes

- Use the virtual environment rather than Kali's system Python; this avoids
  conflicts with distribution-managed packages.
- The installer requires `sudo` only for the optional prerequisite packages.
- The project does not require root after installation. Run it only in an
  authorized assessment scope.
