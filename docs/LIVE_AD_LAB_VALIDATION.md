# Disposable Active Directory lab validation

This procedure is the manual gate for live LDAP, Kerberos, AD CS, coercion,
relay, and destructive rollback behavior. It is intentionally separate from
pull-request CI because it needs a real domain controller.

## Safety rule

Use only a disposable lab that you own or are explicitly authorized to test.
Never point these commands at a production domain. Take VM snapshots before
testing and restore them afterward. The default procedure is read-only; the
mutation step is optional and is only for the isolated lab created here.

## What a novice needs

The simplest setup uses three machines on one private virtual network:

1. **Domain controller:** Windows Server 2022 Evaluation, 4 GB RAM, 2 vCPU,
   40 GB disk.
2. **Optional member workstation:** Windows 10/11 Evaluation, 4 GB RAM, 2 vCPU.
3. **Operator machine:** the host, Kali VM, Linux VM, or Windows machine where
   ADAF-ATTACK is installed.

Hyper-V works on Windows Pro/Enterprise. VirtualBox provides the same result
on other Windows editions, macOS, and Linux. Create an **internal/host-only
network**, not a bridged network. Internet access is needed only to download
evaluation media and approved packages; disconnect the lab VMs before testing.

## Step 1: Create the domain controller

Install Windows Server in the first VM and give it a temporary computer name:

```powershell
Rename-Computer -NewName DC01 -Restart
```

After the restart, open an elevated PowerShell window and install AD DS:

```powershell
Install-WindowsFeature AD-Domain-Services -IncludeManagementTools
$safeModePassword = Read-Host "Choose the disposable Directory Services Restore Mode password" -AsSecureString
Install-ADDSForest -DomainName "lab.example" -DomainNetbiosName "LAB" `
  -InstallDns -SafeModeAdministratorPassword $safeModePassword -Force
```

The VM will restart. Sign in as `LAB\Administrator`, confirm DNS is running,
and take a snapshot named `adaf-lab-clean-domain`.

Do not reuse a company domain name, administrator password, or production DNS
server in this lab.

## Step 2: Create safe test fixtures

Copy [Setup-DisposableAdLab.ps1](../scripts/Setup-DisposableAdLab.ps1) to the
domain controller and run it in an elevated PowerShell window:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\Setup-DisposableAdLab.ps1
```

The script refuses non-`.lab`/`.test` domains and creates only:

- `LAB\adaf-operator`, a disposable operator account;
- `LAB\adaf-service`, a disposable service-account fixture;
- `ADAF-Lab-Readers`, a disposable group;
- `HTTP/adaf-web.lab.example`, a harmless SPN used to exercise discovery.

Use the temporary password only inside the lab. Do not put it in a command
line, evidence bundle, ticket, or report.

## Step 3: Verify the operator machine

On the operator machine, install the approved release and run:

```bash
python -m pip check
adaf-attack doctor --explain
adaf-attack list-capabilities --by-phase
```

If the operator is outside the lab subnet, add a temporary hosts/DNS entry for
the domain controller or configure the lab DNS server. Confirm the operator
can resolve and reach the DC before running ADAF-ATTACK:

```text
dc01.lab.example -> <private lab IP>
lab.example      -> <private lab IP>
```

For Kerberos validation, synchronize VM clocks and use the lab DNS server. Do
not disable time or certificate validation in a production environment.

## Step 4: Run the read-only smoke workflow

Create and review the plan before running it:

```bash
adaf-attack ad-recon profile
adaf-attack ad-recon init --output ad-recon.yaml
adaf-attack engagement validate ad-recon.yaml
```

Edit the generated YAML so that its domain, DC address, username, and target
allowlist refer to the lab only. Then run with the disposable operator account:

```bash
adaf-attack engagement run ad-recon.yaml \
  --workspace ./live-lab-workspace \
  -u adaf-operator
```

Supply the password through the CLI's supported secure prompt or approved
secret mechanism. Do not use `-p` in shell history.

Record the resulting session directory. It should contain findings and an audit
trail. Review it without contacting the domain again:

```bash
adaf-attack sessions --workspace ./live-lab-workspace
adaf-attack engagement report --session ./live-lab-workspace/<session-id> --engagement-id LAB-001
adaf-attack engagement package --session ./live-lab-workspace/<session-id> \
  --output live-lab-evidence.zip --profile client
```

## Step 5: Validate optional capabilities

Run only the rows for tools installed in the approved operator environment:

| Capability | Additional setup | Evidence expected |
|---|---|---|
| LDAP enumeration | Base install and lab account | Domain objects and findings |
| Kerberos/Impacket | `[kerberos]`, correct DNS/time | Kerberos check and sanitized findings |
| AD CS | `[certipy]`, a separately installed test CA | Certificate inventory; no private keys in evidence |
| Relay/coercion | Isolated second VM and explicit approval | Plan/preview and audit record; never production traffic |
| Destructive rollback | Snapshot plus approval token | Refusal without `--force`, then lab-only mutation and rollback |

AD CS and relay fixtures are intentionally not enabled by the baseline setup
script. Add them only from a reviewed lab recipe and snapshot the DC first.

## Step 6: Prove destructive safety

First prove the guard works. This command must refuse to mutate anything:

```bash
adaf-attack --format json cleanup --session ./live-lab-workspace/<session-id> \
  --domain lab.example --dc-ip <private-lab-ip>
```

Only after reviewing the plan, snapshot, and authorization token, repeat the
test in the disposable lab with `--force`. Confirm that the audit log records
the scope, approval, before/after state, and rollback result. Restore the clean
snapshot after validation and rerun the read-only smoke workflow.

## Step 7: Sanitize and validate evidence

Before attaching evidence to a release, remove passwords, tokens, hashes,
private keys, PFX/PEM files, CCache files, and raw credential material. Then
run the offline validator from the repository checkout:

```bash
python scripts/validate_live_lab_run.py \
  --evidence-dir ./live-lab-workspace/<session-id> \
  --require findings.json \
  --require reports/report-manifest.json
```

Expected result:

```text
LIVE LAB EVIDENCE PASSED: ...
```

The validator rejects missing or invalid JSON, likely unredacted sensitive
fields, credential file extensions, and obvious plaintext password assignments.

## Release evidence record

Record this information with the release candidate:

```text
Release/version: ____________________
Commit SHA: _________________________
Lab snapshot: _______________________
Domain/DC: __________________________
Operator OS/Python: _________________
Optional tool versions: _____________
Read-only smoke: PASS / FAIL
Optional capabilities: ______________
Force guard: PASS / FAIL
Lab-only mutation/rollback: PASS / FAIL / NOT RUN
Evidence validator: PASS / FAIL
Sanitized evidence location: ________
Reviewer/date: _______________________
```

A release may claim live-AD readiness only when the required rows are marked
pass and the sanitized evidence is retained with the candidate.
