# ADAF-ATTACK

**Aggressive Active Directory offensive toolkit for senior internal red teamers.**

> Authorized internal red team use only.

## Philosophy

- No plan-only / lab-cert / containment gates
- Lightweight controls: `--force`, redaction by default, session logging

## Capabilities (v0.5.0)

| ID | Category | Description |
|----|----------|-------------|
| `ldap-enum` | enumeration | Users, computers, groups, trusts, SPNs |
| `trusts-enum` | enumeration | Trust direction, SID filtering, forest vs external |
| `adcs-enum` | enumeration | CAs, templates, ESC1 candidates **+ enrollment ACEs** |
| `acl-enum` | enumeration | GenericAll, WriteDacl, WriteOwner, ForceChangePassword, DCSync |
| `gmsa-laps-enum` | enumeration | gMSA inventory, LAPS presence, read ACL signals |
| `kerberoast` | credential-access | hashcat `$krb5tgs$23$` |
| `asrep-roast` | credential-access | hashcat `$krb5asrep$23$` |
| `bloodhound-export` | export | JSON + **zip** for BloodHound CE ingest |

ACL / ADCS enrollment parsing requires Impacket: `pip install 'adaf-attack[kerberos]'`.

## Install

```bash
pip install -e ".[full]"
```

## Examples

```bash
adaf-attack run acl-enum -d corp.local --dc-ip 10.0.0.10 -u alice -p 'Password1'
adaf-attack run gmsa-laps-enum -d corp.local --dc-ip 10.0.0.10 -u alice -p 'Password1'
adaf-attack run adcs-enum -d corp.local --dc-ip 10.0.0.10 -u alice -p 'Password1'
adaf-attack run bloodhound-export -d corp.local --dc-ip 10.0.0.10 -u alice -p 'Password1'
```

`bloodhound.zip` contains `bloodhound.json`, `nodes.json`, `edges.json`, `meta.json`.

## Notes

- **ESC1**: template flags mark *candidates*; enrollment ACEs on the template provide *who can enroll*. Combined → `esc1_with_enroll_principals` / `ESC1Enrollable` edges.
- **gMSA / LAPS**: password *values are never written*. ACL read signals are hints, not a dump.
- **DCSync**: emitted when a principal has both `GetChanges` and `GetChangesAll` on the domain object.

## License

Private. Internal use only.
