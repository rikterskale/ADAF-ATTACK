# Security Policy

ADAF-ATTACK is an aggressive Active Directory offensive toolkit for authorized
internal red-team use. Because the tool ships offensive capabilities, we take
its security posture — and coordinated disclosure of vulnerabilities in it —
seriously.

## Authorized use

ADAF-ATTACK may only be used against Active Directory environments for which
you hold explicit, written authorization. Redistribution is restricted by the
proprietary license. Do not use this toolkit against systems you do not own or
have not been contracted to test.

## Supported versions

Only the latest minor release line receives security fixes. See
[CHANGELOG.md](CHANGELOG.md) for the current version.

| Version | Supported |
|---------|-----------|
| 0.10.x  | Yes       |
| < 0.10  | No        |

## Reporting a vulnerability

Please **do not** open a public GitHub issue for security reports.

Report privately by emailing **security@adaf-attack.invalid** (replace with the
project owner's real address before publishing). Include:

- A clear description of the issue and its impact.
- Reproduction steps or a proof of concept.
- Affected version(s) and platform(s).
- Any suggested mitigation.

For sensitive reports, encrypt to the maintainer PGP key published at
`https://<project-owner>/pgp.asc` (fingerprint: `TO BE ANNOUNCED`).

We acknowledge every report within **3 business days** and aim to publish a
fix, workaround, or disposition within **90 days** of the initial report.
Coordinated disclosure will credit the reporter unless anonymity is requested.

## Out of scope

- Findings that require unauthorized access to a customer environment.
- Reports based on running the tool against systems without authorization.
- Denial-of-service in third-party dependencies without a demonstrated impact
  path through ADAF-ATTACK.
- Missing hardening on private CI infrastructure (not part of the shipped
  product surface).

## Redaction

If your report contains real customer identifiers, credentials, ticket
material, or other secret content, redact them before sending. See
`adaf-attack support-bundle` for the built-in sanitized diagnostic bundle
format.
