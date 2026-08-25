# Known limitations

- The distribution is proprietary and currently delivered through private
  GitHub release assets or authorized source access; it is not on PyPI.
- A scheduled/manual workflow can test published GitHub release wheels, but no
  published artifact is proven until a release with the wheel asset exists and
  that workflow succeeds.
- Hosted CI validates offline CLI behavior and artifact installation. It cannot
  validate live Active Directory, organization-specific endpoint controls,
  proxies, PKI, Kerberos configuration, or authorization systems.
- The automated test suite mocks LDAP, Kerberos, and impacket adapters. A green
  run verifies control flow, argument construction, parsing, redaction, and
  evidence handling — it does not prove behavior against a live domain
  controller. Validate live-target paths against the engagement scope before
  relying on them, and use `--debug` for diagnostic logging when a live run
  misbehaves.
- Kali is validated against a pinned digest of the rolling container. The pin
  must be deliberately refreshed to cover later Kali snapshots.
- Generic Linux distributions share the Python package contract but are not all
  individually hosted. Ubuntu, Windows, macOS, and Kali have explicit artifact
  lanes.
- Certipy is separate from `full` because of dependency constraints. Some
  external operator tools may need dedicated virtual environments.
- Docker is not a live-AD release surface. It is suitable only for offline
  development/reporting because live Kerberos, DNS, SMB, and target-network
  behavior requires host integration.
- Capability safety is enforced from registered profiles, not from engagement
  plan labels. Side-effect operations such as coercion, DCSync, S4U abuse, and
  certificate chains require explicit approval even when they do not directly
  mutate LDAP.
- Destructive capabilities record rollback pre-state in the session
  (`cleanup.json`) and `adaf-attack rollback` reverses supported pending
  changes. Advisory effects such as coercion, certificate enrollment, relay,
  and remote execution still require operator validation against an authorized
  target.
- A generic execution timeout bounds how long the caller waits; it cannot
  force-kill an arbitrary Python or network worker. Timeouts and retries are
  rejected for registered target-mutating or network-side-effect operations.
- Kerberos ccache environment state is scoped to the TGT acquisition call and
  is restored afterward. Long-running integrations should still prefer
  explicit cache paths over process-global environment configuration.
