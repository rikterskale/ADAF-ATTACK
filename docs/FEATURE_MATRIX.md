# Feature and support matrix

This is the user-facing map of what is available after each installation. A
successful base install does not imply that an AD network, credentials, or
external operator tools are available.

| Surface | Install | Extra setup | Network | Mutating | Validation |
|---|---|---|---|---|---|
| CLI, doctor, paths, capability help | Base | None | No | No | CI |
| Packaged offline demo | Base | Writable workspace | No | No | Artifact smoke |
| HTML/PDF reports | `[reports]` / `[full]` | None | No | No | Operator workflow |
| Evidence correlation and packaging | Base | Session evidence | No | No | CI fixtures |
| LDAP/AD reconnaissance | Base | Authorized account, DNS, DC access | Yes | No | Manual lab |
| Kerberos and Impacket adapters | `[kerberos]` / `[full]` | DNS, synchronized clock, realm | Usually | Depends on capability | Manual lab |
| TUI | `[tui]` / `[full]` | Interactive terminal | No | No | CI/source tests |
| AD CS enrollment | `[certipy]` | Certipy on PATH, test CA | Yes | Depends on capability | Manual lab |
| Relay, coercion, destructive workflows | Base plus capability dependencies | Approval token, rollback, disposable lab | Yes | Yes | Manual lab sign-off |
| Promoted offensive IDs (`planned_offensive` catalog) | Base plus capability tools | Authorized account / lab fixtures | Usually | Depends on capability | Manual lab |

## Release status vocabulary

- **CI**: exercised automatically in a clean environment.
- **Manual lab**: requires an authorized disposable AD environment and retained
  sanitized evidence.
- **Experimental**: not currently a release claim; document the limitation in
  the release record before use. The 40 catalog IDs that were previously
  experimental tracking stubs are now `supported` in the live matrix.

## Offline 10-minute acceptance path

From a wheel-only installation, this sequence must succeed without source files:

```bash
python -m pip check
adaf-attack doctor --profile user-readiness
adaf-attack demo --workspace ./demo-session
adaf-attack engagement report --session ./demo-session/demo-session --engagement-id DEMO-2026-001
adaf-attack engagement package --session ./demo-session/demo-session --output demo.zip --profile client
```
