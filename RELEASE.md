# ADAF-ATTACK v0.9.0

## Tier 1
- **shadow-creds** — enum + in-process KeyCredentialLink LDAP write (`--force --write-target`)
- **rbcd** — enum + in-process AllowedToAct SD write (`--force --set-on/--set-from`)
- **gpo-abuse** — writable GPOs and GPLink surfaces
- **report** — session Markdown + HTML operator report

## Tier 2
- **cert-request** — ESC1 enroll playbook (`--force --template`)
- **coercion-map** — detect-only Spooler/EFSRPC map
- TUI: creds-file, scope, start principal
- CLI kwargs for template/CA/alt-name/write-target/RBCD set
- Windows helpers: Report, ShadowCreds, RBCD, PATH install

## Write-path notes
- Shadow creds builds KEYCREDENTIALLINK_BLOB (v2) + DN-Binary and LDAP ADD
- RBCD builds Impacket SR_SECURITY_DESCRIPTOR and LDAP REPLACE
- Both require `--force` and appropriate rights in the target domain
