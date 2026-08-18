# Known limitations

- The distribution is proprietary and currently delivered through private
  GitHub release assets or authorized source access; it is not on PyPI.
- A scheduled/manual workflow can test published GitHub release wheels, but no
  published artifact is proven until a release with the wheel asset exists and
  that workflow succeeds.
- Hosted CI validates offline CLI behavior and artifact installation. It cannot
  validate live Active Directory, organization-specific endpoint controls,
  proxies, PKI, Kerberos configuration, or authorization systems.
- Kali is validated against a pinned digest of the rolling container. The pin
  must be deliberately refreshed to cover later Kali snapshots.
- Generic Linux distributions share the Python package contract but are not all
  individually hosted. Ubuntu, Windows, macOS, and Kali have explicit artifact
  lanes.
- Certipy is separate from `full` because of dependency constraints. Some
  external operator tools may need dedicated virtual environments.
- Destructive capabilities require explicit safeguards, but release sign-off
  still needs a disposable authorized AD lab to prove target-side cleanup.
