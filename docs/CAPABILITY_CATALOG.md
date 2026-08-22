# Capability catalog

This document is regenerated from the running package by
`scripts/generate_capability_catalog.py`. Do not edit by hand; run the
script (CI enforces parity).

| ID | Category | Difficulty | Destructive | Summary |
|----|----------|------------|-------------|---------|
| `aadconnect-dcsync` | credential-access | - | no | Identify and use Azure AD Connect MSOL_* replication rights |
| `acl-abuse` | privilege-escalation | - | yes | Operator ACL abuse: GenericAll / GenericWrite / WriteDacl / WriteOwner / Owns |
| `acl-enum` | enumeration | - | no | Enumerate interesting ACL edges (high-value or domain-wide scope) |
| `acl-write` | privilege-escalation | - | yes | Apply an approved raw ACL descriptor with rollback capture |
| `ad-cve-scan` | enumeration | - | no | Non-exploiting scan for Zerologon / noPAC / Certifried / signing posture |
| `adcs-enum` | enumeration | - | no | Enumerate AD CS CAs/templates, ESC1–ESC9 signals, and enrollment rights |
| `adcs-policy-probe` | enumeration | - | no | Evaluate CA/DC policy evidence for ESC10–ESC15 |
| `add-member` | privilege-escalation | - | yes | Add a principal to a group (AddMember / GenericAll on group) |
| `add-self` | privilege-escalation | - | yes | Add the current principal to a group (AddSelf) |
| `adidns-wpad` | lateral-movement | - | yes | Plant WPAD / wildcard records in AD-integrated DNS |
| `adminsdholder-persist` | persistence | - | yes | Plant a persistence ACE on AdminSDHolder |
| `asrep-roast` | credential-access | - | no | Identify and roast accounts that do not require pre-authentication |
| `asreq-userhunt` | enumeration | - | no | Validate usernames via Kerberos AS-REQ without incrementing badPwdCount |
| `attack-paths` | analysis | - | no | Rank weighted attack paths from principals toward high-value targets |
| `azureadssoacc-roast` | credential-access | - | no | Kerberoast the Seamless SSO computer account (AZUREADSSOACC$) |
| `badsuccessor` | privilege-escalation | - | yes | Windows Server 2025 dMSA BadSuccessor privilege escalation |
| `blast-radius` | analysis | - | no | Calculate reachable high-value impact from a graph principal |
| `bloodhound-export` | export | - | no | Export attack graph to BloodHound CE JSON + ingest zip |
| `bloodhound-import` | export | - | no | Import BloodHound-compatible JSON, enrich locally, and re-export |
| `campaign-run` | analysis | - | yes | Run ordered engagement phases with vault hand-off and purple package |
| `cert-request` | credential-access | - | yes | Request a certificate from AD CS (ESC1 enroll path); requires --force |
| `coerce` | credential-access | - | no | Trigger coercion only against an approved host allowlist |
| `coercion-map` | discovery | - | no | Map coercion surfaces (Spooler/EFSRPC) on domain computers — detect only |
| `computer-takeover` | enumeration | - | no | Identify writable computer SPN and DNS identity surfaces |
| `constrained-delegation` | lateral-movement | - | yes | Abuse constrained delegation (msDS-AllowedToDelegateTo) |
| `credential-inventory` | credential-access | - | yes | Inventory, export, purge, or mark-for-rotation session credential material |
| `dcshadow` | persistence | - | yes | DCShadow replication-based directory modification |
| `dcsync` | credential-access | - | no | Replicate NT/LM/aes secrets via MS-DRSR (DCSync) |
| `dcsync-grant-workflow` | credential-access | - | yes | Grant DS-Replication rights, DCSync, revert the ACE |
| `dmsa-ouroboros` | credential-access | - | yes | Post-patch dMSA Ouroboros credential extraction (Server 2025) |
| `dnsadmin-srv` | privilege-escalation | - | yes | DNSAdmins name-abuse (SRV / WPAD) without a server DLL drop |
| `dpapi-domain-backup` | credential-access | - | no | Retrieve the domain DPAPI backup key via replication rights |
| `esc-chain` | privilege-escalation | - | no | Automated ESC1–ESC15 exploit chain: template → cert → PKINIT → TGT |
| `esc10` | adcs | - | yes | AD CS ESC10: weak certificate mapping |
| `esc13` | adcs | - | yes | AD CS ESC13: issuance policy linked to a privileged group |
| `esc14` | adcs | - | yes | AD CS ESC14: weak explicit certificate mapping |
| `esc15` | adcs | - | yes | AD CS ESC15 (EKUwu / CVE-2024-49019): v1 template application policy override |
| `esc16` | adcs | - | yes | AD CS ESC16: security extension disabled on the CA |
| `esc8-relay-workflow` | adcs | - | yes | Coerce plus HTTP relay to AD CS web enrollment (ESC8) |
| `esc9` | adcs | - | yes | AD CS ESC9: template with no SID security extension |
| `force-change-password` | credential-access | - | yes | Reset a user password via User-Force-Change-Password |
| `gmsa-laps-enum` | credential-access | - | no | Enumerate gMSAs and LAPS; read secrets with --include-secrets when permitted |
| `gmsa-read` | credential-access | - | no | Read and parse msDS-ManagedPassword for a gMSA |
| `golden-cert` | persistence | - | yes | Forge authentication certificates from a stolen CA key |
| `gpo-abuse` | privilege-escalation | - | no | Enumerate writable GPOs with link-based blast-radius ranking |
| `gpo-link` | privilege-escalation | - | yes | Replace an approved GPO link with rollback capture |
| `gpo-sysvol` | privilege-escalation | - | yes | Probe SYSVOL GPO paths for write; optional stage requires --force |
| `gpp-cpassword-hunt` | credential-access | - | no | Discover and decrypt legacy GPP cpassword secrets under SYSVOL |
| `hybrid-signals` | enumeration | - | no | Detect on-prem hybrid identity / Entra-adjacent signals (read-only) |
| `impacket-exec` | lateral-movement | - | yes | Remote execute via wmiexec / smbexec / dcomexec / atexec |
| `kerberoast` | credential-access | - | no | Request TGS tickets for SPN-enabled accounts (Kerberoasting) |
| `krb-relay` | lateral-movement | - | yes | Kerberos relay / reflection into LDAP, SMB, or HTTP |
| `laps-read` | credential-access | - | no | Read LAPS v1 (ms-Mcs-AdmPwd) and v2 (msLAPS-EncryptedPassword) passwords |
| `ldap-enum` | enumeration | - | no | Enumerate users, computers, groups, trusts, SPNs, delegation, SID history, and GPO links via LDAP |
| `maq-add-computer` | privilege-escalation | - | yes | Create a machine account using ms-DS-MachineAccountQuota |
| `maq-rbcd-workflow` | lateral-movement | - | yes | MachineAccountQuota add-computer then RBCD then S4U |
| `next-actions` | analysis | - | no | Recommend policy-gated next actions from current graph evidence only |
| `nopac-workflow` | privilege-escalation | - | yes | sAMAccountName spoof (noPac / CVE-2021-42278/42287) workflow |
| `ntlm-relay` | lateral-movement | - | yes | Run ntlmrelayx against a fixed allowlist; vault captured credentials |
| `password-spray` | credential-access | - | no | Lockout-aware password spray against user accounts |
| `pkinit-auth` | credential-access | - | yes | PKINIT TGT using shadow-cred key/cert from session (requires --force) |
| `pre2k-spray` | credential-access | - | no | Pre-Windows 2000 compatible computer accounts (password = sAMAccountName) |
| `purple-feedback` | export | - | no | Generate updated detection hypotheses from session events |
| `rbcd` | lateral-movement | - | yes | Enumerate RBCD + constrained delegation; optional set requires --force |
| `rbcd-ticket-workflow` | lateral-movement | - | yes | Set RBCD then request a service ticket when an approved provider is available |
| `report` | export | - | no | Generate operator Markdown/HTML report from current session artifacts |
| `rodc-delegation` | enumeration | - | no | Enumerate RODC password-replication policy, KRBTGT, and delegation exposure |
| `rollback` | analysis | - | yes | Reverse pending destructive changes recorded in a session (requires --force) |
| `s4u-abuse` | privilege-escalation | - | no | Full S4U2Self + S4U2Proxy chain (constrained delegation / RBCD abuse) |
| `sccm-client-push` | lateral-movement | - | yes | Abuse SCCM client-push installation account |
| `sccm-enum` | enumeration | - | no | Enumerate Microsoft Configuration Manager (SCCM/MECM) attack surface |
| `sccm-naa` | credential-access | - | no | Recover SCCM Network Access Account credentials |
| `sccm-takeover` | privilege-escalation | - | yes | SCCM site takeover via relay to the site database (TAKEOVER-1) |
| `secretsdump-local` | credential-access | - | no | Dump SAM/LSA/NLKM/DPAPI secrets from a host (registry / LSA, no NTDS) |
| `shadow-creds` | credential-access | - | yes | Enumerate msDS-KeyCredentialLink; optional write requires --force |
| `shadow-pkinit-workflow` | credential-access | - | yes | Write Shadow Credential then request PKINIT TGT (requires --force) |
| `sidhistory-inject` | privilege-escalation | - | yes | Inject SID History / ExtraSids on a controlled principal |
| `sysvol-hunt` | credential-access | - | no | Search authorized SYSVOL evidence for GPP cpasswords, scripts, and tasks |
| `targeted-kerberoast` | credential-access | - | yes | Write SPN, Kerberoast, revert SPN |
| `template-mod` | privilege-escalation | - | yes | Flip AD CS template to ESC1-vulnerable with rollback registration |
| `ticket-forge` | credential-access | - | no | Forge golden / silver / sapphire Kerberos tickets from krbtgt / service key |
| `ticket-lifecycle` | credential-access | - | no | Inventory or import ticket/certificate artifacts into the session vault |
| `timeroast` | credential-access | - | no | Unauthenticated RID roast via NTP (Timeroasting) |
| `trustedtoauth` | lateral-movement | - | no | Protocol-transition constrained delegation (TrustedToAuthForDelegation) |
| `trusts-enum` | enumeration | - | no | Deep trust enumeration with SID-filtering attack-path analysis |
| `unconst-tgtdump-workflow` | credential-access | - | yes | Unconstrained-delegation hunt then coerce to capture a TGT |
| `unconstrained-delegation` | enumeration | - | no | Hunt computers trusted for unconstrained delegation (TGT delegation) |
| `unpac-the-hash` | credential-access | - | no | Recover NT hash from a PKINIT-only cert by parsing PAC_CREDENTIAL_INFO |
| `write-spn` | credential-access | - | yes | Set or clear servicePrincipalName for targeted Kerberoast |
