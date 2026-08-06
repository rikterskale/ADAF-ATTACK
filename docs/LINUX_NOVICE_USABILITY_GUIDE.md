---
guide_id: linux-novice-usability
guide_schema_version: 1
platform: linux
canonical_path: docs/guides/LINUX_NOVICE_USABILITY_GUIDE.md
project_name: ADAF-ATTACK
target_release: 0.10.0
target_commit: unavailable-source-archive-no-git-metadata
support_status: native_supported
alternative_support_paths: []
validation_status: statically_verified_only
validated_on: 2026-08-06
validated_environments: []
primary_shells: ["Bash"]
maintainer_source_of_truth: pyproject.toml
known_limitations: ["No clean linux journey", "No authorized AD lab"]
---

# ADAF-ATTACK Linux Novice Usability Guide

## About This Guide

Follow the recommended isolated source-install path. Target-interacting procedures are intentionally excluded from the safe novice first run.

## What This Project Does

Follow the recommended isolated source-install path. Target-interacting procedures are intentionally excluded from the safe novice first run.

## Who Should Use It

Follow the recommended isolated source-install path. Target-interacting procedures are intentionally excluded from the safe novice first run.

## Safety, Authorization, and Data Handling

Use only with written authorization. Do not use `--force` or `--include-secrets` during onboarding. Treat workspaces as sensitive evidence.

## Platform Support Status

Package metadata claims Linux support with Python 3.11 through 3.13. This complete clean path was not runtime validated.

## What You Will Accomplish

Follow the recommended isolated source-install path. Target-interacting procedures are intentionally excluded from the safe novice first run.

## Before You Begin Checklist

Follow the recommended isolated source-install path. Target-interacting procedures are intentionally excluded from the safe novice first run.

## Computer and Software Requirements

Follow the recommended isolated source-install path. Target-interacting procedures are intentionally excluded from the safe novice first run.

## Terms and Concepts You Need to Know

Repository means project folder; terminal means command application; shell interprets commands; working directory is the active folder; runtime executes Python; dependency is required software; package manager installs software; virtual environment isolates Python packages; environment variable is named configuration; exit code zero usually means success; process is a running program; port or listener accepts network traffic; artifact is generated evidence; clone copies; update refreshes; rollback reverses; cleanup removes created state.

## Choose the Correct Installation Path

Follow the recommended isolated source-install path. Target-interacting procedures are intentionally excluded from the safe novice first run.

## Open the Correct Terminal or Shell

Follow the recommended isolated source-install path. Target-interacting procedures are intentionally excluded from the safe novice first run.

## Check and Install Prerequisites

**Command ID:** LNX-CMD-001  
**Purpose:** prerequisite check  
**Run in:** Bash  
**Working directory:** any folder  
**Privilege required:** ordinary user  
**Internet access:** not required  
**Safe to copy and paste:** yes  
**Replace before running:** none  
**Expected side effects:** none  
**Validation status:** statically verified

```bash
python3 --version
```

Expected exit status: 0. Output is Code-Derived Output Shape. Continue when a supported version is shown.

**Command ID:** LNX-CMD-002  
**Purpose:** prerequisite check  
**Run in:** Bash  
**Working directory:** any folder  
**Privilege required:** ordinary user  
**Internet access:** not required  
**Safe to copy and paste:** yes  
**Replace before running:** none  
**Expected side effects:** none  
**Validation status:** statically verified

```bash
git --version
```

Expected exit status: 0. Output is Code-Derived Output Shape. Continue when a supported version is shown.


## Download or Clone the Repository

Follow the recommended isolated source-install path. Target-interacting procedures are intentionally excluded from the safe novice first run.

## Find and Enter the Repository Folder

Follow the recommended isolated source-install path. Target-interacting procedures are intentionally excluded from the safe novice first run.

## Create an Isolated Environment

**Command ID:** LNX-CMD-003  
**Purpose:** create an isolated environment  
**Run in:** Bash  
**Working directory:** repository root  
**Privilege required:** ordinary user  
**Internet access:** not required  
**Safe to copy and paste:** yes  
**Replace before running:** none  
**Expected side effects:** creates or removes .venv  
**Validation status:** statically verified

```bash
python3 -m venv .venv
```

Expected exit status: 0. Output is Code-Derived Output Shape. See troubleshooting if it fails.

## Install Project Dependencies

**Command ID:** LNX-CMD-004  
**Purpose:** install project dependencies  
**Run in:** Bash  
**Working directory:** repository root  
**Privilege required:** ordinary user  
**Internet access:** required  
**Safe to copy and paste:** yes  
**Replace before running:** none  
**Expected side effects:** creates or removes .venv  
**Validation status:** statically verified

```bash
.venv/bin/python -m pip install -e ".[full]"
```

Expected exit status: 0. Output is Code-Derived Output Shape. See troubleshooting if it fails.

## Build or Install the Project

Follow the recommended isolated source-install path. Target-interacting procedures are intentionally excluded from the safe novice first run.

## Verify the Installation

**Command ID:** LNX-CMD-005  
**Purpose:** verify the installation  
**Run in:** Bash  
**Working directory:** repository root  
**Privilege required:** ordinary user  
**Internet access:** not required  
**Safe to copy and paste:** yes  
**Replace before running:** none  
**Expected side effects:** none  
**Validation status:** statically verified

```bash
.venv/bin/python -m adaf_attack.cli --version
```

Expected exit status: 0. Output is Code-Derived Output Shape. See troubleshooting if it fails.

## Complete the First Safe Successful Run

**Command ID:** LNX-CMD-006  
**Purpose:** complete the first safe successful run  
**Run in:** Bash  
**Working directory:** repository root  
**Privilege required:** ordinary user  
**Internet access:** not required  
**Safe to copy and paste:** yes  
**Replace before running:** none  
**Expected side effects:** none  
**Validation status:** statically verified

```bash
.venv/bin/python -m adaf_attack.cli doctor
```

Expected exit status: 0. Output is Code-Derived Output Shape. See troubleshooting if it fails.

## Understand the Screen Output, Exit Status, and Result Files

Follow the recommended isolated source-install path. Target-interacting procedures are intentionally excluded from the safe novice first run.

## Common Novice Workflows

**Command ID:** LNX-CMD-007  
**Purpose:** common novice workflows  
**Run in:** Bash  
**Working directory:** repository root  
**Privilege required:** ordinary user  
**Internet access:** not required  
**Safe to copy and paste:** yes  
**Replace before running:** none  
**Expected side effects:** none  
**Validation status:** statically verified

```bash
.venv/bin/python -m adaf_attack.cli list-capabilities
```

Expected exit status: 0. Output is Code-Derived Output Shape. See troubleshooting if it fails.

## Configuration, Environment Variables, and Credentials

Follow the recommended isolated source-install path. Target-interacting procedures are intentionally excluded from the safe novice first run.

## How to Stop or Cancel Safely

Follow the recommended isolated source-install path. Target-interacting procedures are intentionally excluded from the safe novice first run.

## Cleanup, Uninstall, and Host Restoration

**Command ID:** LNX-CMD-008  
**Purpose:** cleanup, uninstall, and host restoration  
**Run in:** Bash  
**Working directory:** repository root  
**Privilege required:** ordinary user  
**Internet access:** not required  
**Safe to copy and paste:** yes  
**Replace before running:** none  
**Expected side effects:** creates or removes .venv  
**Validation status:** statically verified

```bash
rm -rf .venv
```

Expected exit status: 0. Output is Code-Derived Output Shape. See troubleshooting if it fails.

## Update, Upgrade, Downgrade, and Rollback

Follow the recommended isolated source-install path. Target-interacting procedures are intentionally excluded from the safe novice first run.

## Troubleshooting Matrix

| ID | Symptom | Likely cause | Exact fix | Verify |
|---|---|---|---|---|
| TRB-001 | `No module named adaf_attack` | wrong interpreter or install missing | repeat the editable install with the `.venv` Python | rerun the version command |
| TRB-002 | LDAP bind failed | scope, identity, protocol, or credential problem | stop, reconfirm authorization and inputs, and collect sanitized session events | authorized lab operator validates |

## Frequently Asked Questions

Follow the recommended isolated source-install path. Target-interacting procedures are intentionally excluded from the safe novice first run.

## Command Quick Reference

- `LNX-CMD-001`: `python3 --version`
- `LNX-CMD-002`: `git --version`
- `LNX-CMD-003`: `python3 -m venv .venv`
- `LNX-CMD-004`: `.venv/bin/python -m pip install -e ".[full]"`
- `LNX-CMD-005`: `.venv/bin/python -m adaf_attack.cli --version`
- `LNX-CMD-006`: `.venv/bin/python -m adaf_attack.cli doctor`
- `LNX-CMD-007`: `.venv/bin/python -m adaf_attack.cli list-capabilities`
- `LNX-CMD-008`: `rm -rf .venv`

## Glossary

Repository means project folder; terminal means command application; shell interprets commands; working directory is the active folder; runtime executes Python; dependency is required software; package manager installs software; virtual environment isolates Python packages; environment variable is named configuration; exit code zero usually means success; process is a running program; port or listener accepts network traffic; artifact is generated evidence; clone copies; update refreshes; rollback reverses; cleanup removes created state.

## Validation Record, Known Limitations, and Support Boundaries

Follow the recommended isolated source-install path. Target-interacting procedures are intentionally excluded from the safe novice first run.
