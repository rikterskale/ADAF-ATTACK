# Kali Linux support

ADAF-ATTACK supports Kali Linux with Python 3.11 or newer. It uses the standard
XDG data locations, so session artifacts default to
`~/.local/share/adaf-attack/workspaces`.

## Install

Clone/extract the matching source release, place the approved wheel in `dist`,
then run the installer from the repository root:

```bash
bash scripts/install-kali.sh --package dist/adaf_attack-0.10.0-py3-none-any.whl
source .venv/bin/activate
adaf-attack doctor
```

The installer installs the build and Python prerequisites through `apt`, then
creates a project-local `.venv` and installs the production `full` extra set. To use
already-provisioned packages, omit the `apt` step:

```bash
bash scripts/install-kali.sh --skip-system-deps
```

Select a smaller dependency set with `--extras base`, `--extras tui`, or
`--extras kerberos`. Omitting `--package` installs the authorized source
checkout.

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

## Upgrade and uninstall

Rerun the installer with a newer or older approved artifact to change versions.
The default uninstall removes only the venv and preserves workspace evidence:

```bash
bash scripts/install-kali.sh --uninstall
```

Delete workspace data only after retention approval:

```bash
bash scripts/install-kali.sh --uninstall --remove-workspace
```

## Notes

- Use the virtual environment rather than Kali's system Python; this avoids
  conflicts with distribution-managed packages.
- The installer requires `sudo` only for the optional prerequisite packages.
- The project does not require root after installation. Run it only in an
  authorized assessment scope.
- Hosted CI performs a real artifact install in a Kali rolling container, but it
  cannot prove your endpoint policy or live AD environment.
