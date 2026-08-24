# Rollback matrix

Every destructive capability records pre-change state in the session's
`cleanup.json` ledger. This matrix shows what each rollback kind covers,
what it reverts, and what it cannot.

## Revertable kinds

These kinds have automated rollback handlers. The `rollback` capability
can reverse them with `--force`:

```bash
adaf-attack run rollback -d corp.local --dc-ip 10.0.0.10 \
  -P session=./workspaces/<session> --force
```

| Kind | What it reverts | What it records | Capabilities that use it |
|------|----------------|-----------------|--------------------------|
| `acl-write` | ACL descriptor written to a directory object | Previous `nTSecurityDescriptor` | `acl-write` |
| `acl` | ACE added or modified on a directory object | Previous ACE state | `acl-abuse`, `dcsync-grant-workflow`, `adminsdholder-persist` |
| `computer-identity` | Machine account SPN or DNS identity change | Previous `servicePrincipalName`, `dNSHostName` | `computer-takeover`, `nopac-workflow` |
| `ldap-attribute` | Single LDAP attribute modification | Previous attribute value | `shadow-creds`, `rbcd`, `force-change-password`, `template-mod` |
| `ldap-add-value` | Value added to a multi-valued attribute | The added value (for removal) | `add-member`, `add-self`, `sidhistory-inject` |
| `ldap-object` | New LDAP object created | Object DN (for deletion) | `maq-add-computer` |
| `rbcd` | `msDS-AllowedToActOnBehalfOfOtherIdentity` set | Previous delegation value | `rbcd`, `maq-rbcd-workflow`, `rbcd-ticket-workflow` |
| `shadow-creds` | `msDS-KeyCredentialLink` written | Previous key credential entries | `shadow-creds`, `shadow-pkinit-workflow` |
| `shadow-credential` | Alias for `shadow-creds` | Same as `shadow-creds` | Legacy compatibility |
| `keycred-write` | Key credential link written | Previous value | `shadow-creds` variants |
| `gpo-link` | GPO link replaced | Previous `gPLink` attribute value | `gpo-link` |
| `template-mod` | AD CS template modified to ESC1-vulnerable | Previous template attributes | `template-mod` |
| `gpo-sysvol` | File staged in SYSVOL GPO path | Staged file path | `gpo-sysvol` |
| `local-artifact` | Local file created during the run | File path (for cleanup) | Various |

## Advisory kinds

These kinds track effects that require operator judgment or a separate
procedure to reverse. The rollback capability surfaces them but does not
attempt automated reversal.

| Kind | Effect | Why manual | Capabilities that use it |
|------|--------|-----------|--------------------------|
| `coercion` | NTLM/Kerberos authentication coerced from a machine | Cannot "un-coerce"; the authentication already happened | `coerce`, `unconst-tgtdump-workflow` |
| `gpo-abuse` | GPO writable state exploited | Depends on what the operator did with the write access | `gpo-abuse` |
| `gmsa` | gMSA password read | Cannot un-read a secret; rotation is the mitigation | `gmsa-read` |
| `krb-relay` | Kerberos relay executed | Relayed authentication cannot be recalled | `krb-relay` |
| `ntlm-challenge` | NTLM challenge captured | Hash was exposed; password rotation required | `coerce` variants |
| `ntlm-hash` | NT hash extracted via DCSync or dump | Hash was exposed; password rotation required | `dcsync`, `secretsdump-local` |
| `ntlm-relay` | NTLM relay executed | Relayed authentication cannot be recalled | `ntlm-relay`, `esc8-relay-workflow` |
| `password-reset` | User password forcibly changed | Original password is unknown; coordinate with the account owner | `force-change-password` |
| `remote-exec` | Remote command executed on a host | Cannot undo arbitrary command effects | `impacket-exec` |
| `rodc` | RODC delegation exposure read | Read-only; rotation is the mitigation | `rodc-delegation` |
| `sccm-push` | SCCM client-push account abused | Depends on the push payload | `sccm-client-push`, `sccm-takeover` |
| `cert-enroll` | Certificate enrolled from AD CS | Certificate must be revoked by the CA administrator | `cert-request`, `esc-chain` |
| `certificate-enroll` | Alias for `cert-enroll` | Same as `cert-enroll` | Legacy compatibility |

## Rollback lifecycle

```
Capability runs ──► record_pre_state() ──► cleanup.json (status: pending)
                                                │
                                                ▼
                    rollback capability ──► attempts revert
                                                │
                                    ┌───────────┴───────────┐
                                    ▼                       ▼
                              status: completed       status: failed
```

### Inspecting rollback state

```bash
# Human-readable cleanup dashboard
adaf-attack cleanup-status --session ./workspaces/<session>

# Machine-readable summary
adaf-attack --format json cleanup-status --session ./workspaces/<session>
```

The dashboard shows `pending`, `completed`, and `failed` counts, grouped
by kind and classification.

### Post-engagement checklist

After running the `rollback` capability:

1. Confirm the target state matches expectations (LDAP query, ACL dump).
2. Document any `advisory` items that require separate action:
   - Revoke issued certificates with the CA administrator.
   - Coordinate password resets for force-changed accounts.
   - Rotate gMSA/LAPS passwords if secrets were read.
   - Review hosts where remote commands were executed.
3. Document any `failed` rollback entries and their manual resolution.
4. Attach the cleanup dashboard output to the engagement report.
