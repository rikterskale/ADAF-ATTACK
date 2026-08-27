# Kali Linux support

ADAF-ATTACK supports Kali Linux with Python 3.11-3.14. It uses the standard
XDG data locations, so session artifacts default to
`~/.local/share/adaf-attack/workspaces` (confirm with `adaf-attack paths`).

## Choose this path when

You are on Kali and have an approved private release wheel (or authorized
checkout). Do not invent a public PyPI URL.

## Install

Clone/extract the matching source release, place the approved wheel in `dist`,
then run the installer from the repository root:

```bash
bash scripts/install-kali.sh --package dist/adaf_attack-0.10.1-py3-none-any.whl
source .venv/bin/activate
```

The installer installs the build and Python prerequisites through `apt`, then
creates a project-local `.venv` and installs the production `full` extra set. To
use already-provisioned packages, omit the `apt` step:

```bash
bash scripts/install-kali.sh --skip-system-deps --package dist/adaf_attack-0.10.1-py3-none-any.whl
```

Select a smaller dependency set with `--extras base`, `--extras tui`, or
`--extras kerberos`. Omitting `--package` installs the authorized source
checkout.

For automation, pass `--json` to receive structured installer failures with a
stable error code, message, remediation, and suggested command.

## Verify (first ten minutes)

```bash
python -m pip check
adaf-attack --version
adaf-attack --format json doctor --profile user-readiness --explain
adaf-attack quickstart --workspace ./quickstart
adaf-attack --format json guide --workspace ./quickstart --session ./quickstart/demo-session
adaf-attack --format json paths
```

Expect exit `0`, doctor `"ready": true`, and one copy-ready `suggested_command`
from `guide`. These checks do not contact a domain controller.

`doctor` reports `Kali Linux` when `/etc/os-release` identifies the host as
Kali. Override workspace location without changing the installer:

```bash
export ADAF_ATTACK_WORKSPACE="$HOME/adaf-workspaces"
```

**When lost:** `adaf-attack guide --workspace ./quickstart --session ./quickstart/demo-session`

## Upgrade and uninstall

Rerun the installer with a newer or older approved artifact to change versions.
The default uninstall removes only the venv and **preserves** workspace evidence:

```bash
bash scripts/install-kali.sh --uninstall
```

Delete workspace data only after retention approval (confirm path with
`adaf-attack paths` first):

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
- Support: `adaf-attack support-bundle --output adaf-support-bundle.json` (redacted).
