# Supported platforms and architectures

The package contract is intentionally narrower than “any Python 3.11-3.13 host.”
Only the rows marked CI-tested are release-supported without additional
sign-off.

| Platform | Architecture | Python | Status |
|---|---|---|---|
| Ubuntu 24.04 | x86_64 | 3.11–3.13 | CI-tested source, wheel, and sdist paths |
| Windows 10/11/Server 2022 | x86_64 | 3.11–3.13 | CI-tested source, wheel, and installers |
| macOS 14 | arm64 runner | 3.11–3.13 | CI-tested wheel path |
| Kali rolling | x86_64 | 3.11–3.13 | CI-tested pinned container and installer |
| Other Linux distributions | x86_64 or arm64 | 3.11–3.13 | Package contract; manual validation required |
| Windows on ARM | arm64 | 3.11–3.13 | Not release-tested; use emulation only with sign-off |
| Linux ARM64 | arm64 | 3.11–3.13 | Not release-tested; native dependency availability may vary |

No GPU is required. Live Kerberos and LDAP workflows require working DNS,
network reachability to the authorized domain controller, synchronized clocks,
and the optional operator dependencies described in
[USER_READINESS.md](USER_READINESS.md).

For a new host, run the safe check before connecting to a target:

```bash
adaf-attack --format json doctor --explain
adaf-attack --format json paths
```

For a broader local check, use `doctor --profile operator`. Only the explicit
`doctor --profile live-ad --domain <domain> --dc-ip <dc>` form performs DNS and
TCP preflight probes; the default profile is offline-safe.

If a platform or architecture is not listed as CI-tested, treat it as a manual
compatibility validation and retain the output with the release evidence.
