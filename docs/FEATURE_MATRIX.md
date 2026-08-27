# Feature and support matrix

This is the user-facing map of what is available after each installation. A
successful base install does not imply that an AD network, credentials, or
external operator tools are available.

| Surface | Install | Extra setup | Network | Mutating | Validation |
|---|---|---|---|---|---|
| CLI, doctor, paths, capability help | Base | None | No | No | CI |
| Guided journey (`guide` / `what-next` / TUI Home) | Base | Writable workspace | No | No | CI |
| Packaged offline demo | Base | Writable workspace | No | No | Artifact smoke |
| HTML/PDF reports | `[reports]` / `[full]` | None | No | No | Operator workflow |
| Evidence correlation and packaging | Base | Session evidence | No | No | CI fixtures |
| LDAP/AD reconnaissance | Base | Authorized account, DNS, DC access | Yes | No | Operator-verified |
| Kerberos and Impacket adapters | `[kerberos]` / `[full]` | DNS, synchronized clock, realm | Usually | Depends on capability | Operator-verified |
| TUI | `[tui]` / `[full]` | Interactive terminal | No | No | CI/source tests |
| AD CS enrollment | `[certipy]` | Certipy on PATH, approved CA | Yes | Depends on capability | Operator-verified |
| Relay, coercion, credential-exposure, destructive workflows | Base plus capability dependencies | Registered safety profile, approval token, rollback, authorized target | Yes | Depends on operation | Operator-verified |
| Promoted offensive IDs (capability catalog) | Base plus capability tools | Authorized account / test fixtures | Usually | Depends on capability | Operator-verified |

Capability listings expose an explicit maturity value (`implemented`,
`fixture-tested`, `operator-verified`, or `playbook-only`) together with the
expected environment, external tools, and fixture identifier. Metadata does
not claim live AD validation by itself.

## Release status vocabulary

- **CI**: exercised automatically in a clean environment.
- **Operator-verified**: exercised against an authorized target by the
  operator.
- **Experimental / playbook-only**: not a release claim of live AD success;
  document any limitation in the release record before use. The 40 catalog IDs
  added in 0.10.0 that were previously experimental tracking stubs now have
  registered runners with maturity metadata (`implemented` /
  `fixture-tested` / `operator-verified` / `playbook-only`) — that is not the
  same as CI-proven live forest behavior. The full catalog contains 90+
  capabilities (see [CAPABILITY_CATALOG.md](CAPABILITY_CATALOG.md)).

## Offline 10-minute acceptance path

From a wheel-only installation, this sequence must succeed without source files.
It matches [USER_READINESS.md](USER_READINESS.md) and the README Quick start:

```bash
python -m pip check
adaf-attack --version
adaf-attack --format json doctor --profile user-readiness --explain
adaf-attack quickstart --workspace ./quickstart
adaf-attack --format json guide --workspace ./quickstart --session ./quickstart/demo-session
adaf-attack --format json paths
```

Expect doctor `"ready": true` and one copy-ready `suggested_command` from
`guide`. When lost: `adaf-attack guide` with the same workspace/session.

Optional checks **after** first success (still no DC). `workflow next` must
emit the same `suggested_command` as `guide` for this snapshot:

```bash
adaf-attack --format json workflow next --workspace ./quickstart --session ./quickstart/demo-session
adaf-attack engagement report --session ./quickstart/demo-session --engagement-id DEMO-2026-001
adaf-attack engagement package --session ./quickstart/demo-session --output demo.zip --profile client
```
