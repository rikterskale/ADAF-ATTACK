# Capability catalog

This document is regenerated from the running package by
`scripts/generate_capability_catalog.py`. Do not edit by hand; run the
script (CI enforces parity).

| ID | Category | Maturity | Environment | Tools | Fixture | Difficulty | Destructive | Summary |
|----|----------|----------|-------------|-------|---------|------------|-------------|---------|
| `aadconnect-dcsync` | credential-access | fixture-tested | live-read-only | impacket | hybrid-lab | - | no | Identify and use Azure AD Connect MSOL_* replication rights |
| `acl-abuse` | privilege-escalation | fixture-tested | live-mutating | - | delegated-acl-target | - | yes | Operator ACL abuse: GenericAll / GenericWrite / WriteDacl / WriteOwner / Owns |
| `acl-enum` | enumeration | implemented | unknown | - | - | - | no | Enumerate interesting ACL edges (high-value or domain-wide scope) |
| `acl-write` | privilege-escalation | implemented | unknown | - | - | - | yes | Apply an approved raw ACL descriptor with rollback capture |
| `ad-cve-scan` | enumeration | implemented | unknown | - | - | - | no | Non-exploiting scan for Zerologon / noPAC / Certifried / signing posture |
| `adcs-enum` | enumeration | implemented | unknown | - | - | - | no | Enumerate AD CS CAs/templates, ESC1–ESC9 signals, and enrollment rights |
| `adcs-policy-probe` | enumeration | implemented | unknown | - | - | - | no | Evaluate CA/DC policy evidence for ESC10–ESC15 |
| `add-member` | privilege-escalation | fixture-tested | live-mutating | - | delegated-acl-target | - | yes | Add a principal to a group (AddMember / GenericAll on group) |
| `add-self` | privilege-escalation | fixture-tested | live-mutating | - | delegated-acl-target | - | yes | Add the current principal to a group (AddSelf) |
| `adidns-wpad` | lateral-movement | fixture-tested | live-mutating | - | dns-lab | - | yes | Plant WPAD / wildcard records in AD-integrated DNS |
| `adminsdholder-persist` | persistence | fixture-tested | live-mutating | - | domain-admin-lab | - | yes | Plant a persistence ACE on AdminSDHolder |
| `asrep-roast` | credential-access | implemented | unknown | - | - | - | no | Identify and roast accounts that do not require pre-authentication |
| `asreq-userhunt` | enumeration | implemented | unknown | - | - | - | no | Validate usernames via Kerberos AS-REQ without incrementing badPwdCount |
| `attack-paths` | analysis | implemented | unknown | - | - | - | no | Rank weighted attack paths from principals toward high-value targets |
| `azureadssoacc-roast` | credential-access | fixture-tested | live-read-only | impacket | hybrid-lab | - | no | Kerberoast the Seamless SSO computer account (AZUREADSSOACC$) |
| `badsuccessor` | privilege-escalation | fixture-tested | live-mutating | - | dmsa-lab | - | yes | Windows Server 2025 dMSA BadSuccessor privilege escalation |
| `blast-radius` | analysis | implemented | unknown | - | - | - | no | Calculate reachable high-value impact from a graph principal |
| `bloodhound-export` | export | implemented | unknown | - | - | - | no | Export attack graph to BloodHound CE JSON + ingest zip |
| `bloodhound-import` | export | implemented | unknown | - | - | - | no | Import BloodHound-compatible JSON, enrich locally, and re-export |
| `campaign-run` | analysis | implemented | unknown | - | - | - | yes | Run ordered engagement phases with vault hand-off and purple package |
| `cert-request` | credential-access | implemented | unknown | - | - | - | yes | Request a certificate from AD CS (ESC1 enroll path); requires --force |
| `coerce` | credential-access | implemented | unknown | - | - | - | no | Trigger coercion only against an approved host allowlist |
| `coercion-map` | discovery | implemented | unknown | - | - | - | no | Map coercion surfaces (Spooler/EFSRPC) on domain computers — detect only |
| `computer-takeover` | enumeration | implemented | unknown | - | - | - | no | Identify writable computer SPN and DNS identity surfaces |
| `constrained-delegation` | lateral-movement | fixture-tested | live-mutating | impacket | delegated-service | - | yes | Abuse constrained delegation (msDS-AllowedToDelegateTo) |
| `credential-inventory` | credential-access | implemented | unknown | - | - | - | yes | Inventory, export, purge, or mark-for-rotation session credential material |
| `dcshadow` | persistence | fixture-tested | live-mutating | impacket | disposable-dc | - | yes | DCShadow replication-based directory modification |
| `dcsync` | credential-access | implemented | unknown | - | - | - | no | Replicate NT/LM/aes secrets via MS-DRSR (DCSync) |
| `dcsync-grant-workflow` | credential-access | fixture-tested | live-mutating | impacket | delegated-acl-target | - | yes | Grant DS-Replication rights, DCSync, revert the ACE |
| `dmsa-ouroboros` | credential-access | fixture-tested | live-mutating | - | dmsa-lab | - | yes | Post-patch dMSA Ouroboros credential extraction (Server 2025) |
| `dnsadmin-srv` | privilege-escalation | fixture-tested | live-mutating | - | dns-lab | - | yes | DNSAdmins name-abuse (SRV / WPAD) without a server DLL drop |
| `dpapi-domain-backup` | credential-access | fixture-tested | live-read-only | impacket | delegated-replication | - | no | Retrieve the domain DPAPI backup key via replication rights |
| `esc-chain` | privilege-escalation | implemented | unknown | - | - | - | no | Automated ESC1–ESC15 exploit chain: template → cert → PKINIT → TGT |
| `esc10` | adcs | fixture-tested | live-mutating | certipy | adcs-lab | - | yes | AD CS ESC10: weak certificate mapping |
| `esc13` | adcs | fixture-tested | live-mutating | certipy | adcs-lab | - | yes | AD CS ESC13: issuance policy linked to a privileged group |
| `esc14` | adcs | fixture-tested | live-mutating | certipy | adcs-lab | - | yes | AD CS ESC14: weak explicit certificate mapping |
| `esc15` | adcs | fixture-tested | live-mutating | certipy | adcs-lab | - | yes | AD CS ESC15 (EKUwu / CVE-2024-49019): v1 template application policy override |
| `esc16` | adcs | fixture-tested | live-mutating | certipy | adcs-lab | - | yes | AD CS ESC16: security extension disabled on the CA |
| `esc8-relay-workflow` | adcs | fixture-tested | live-mutating | impacket, certipy | adcs-lab | - | yes | Coerce plus HTTP relay to AD CS web enrollment (ESC8) |
| `esc9` | adcs | fixture-tested | live-mutating | certipy | adcs-lab | - | yes | AD CS ESC9: template with no SID security extension |
| `force-change-password` | credential-access | fixture-tested | live-mutating | - | delegated-acl-target | - | yes | Reset a user password via User-Force-Change-Password |
| `gmsa-laps-enum` | credential-access | implemented | unknown | - | - | - | no | Enumerate gMSAs and LAPS; read secrets with --include-secrets when permitted |
| `gmsa-read` | credential-access | fixture-tested | live-read-only | - | gmsa-laps | - | no | Read and parse msDS-ManagedPassword for a gMSA |
| `golden-cert` | persistence | fixture-tested | live-mutating | certipy | adcs-lab | - | yes | Forge authentication certificates from a stolen CA key |
| `gpo-abuse` | privilege-escalation | implemented | unknown | - | - | - | no | Enumerate writable GPOs with link-based blast-radius ranking |
| `gpo-link` | privilege-escalation | implemented | unknown | - | - | - | yes | Replace an approved GPO link with rollback capture |
| `gpo-sysvol` | privilege-escalation | implemented | unknown | - | - | - | yes | Probe SYSVOL GPO paths for write; optional stage requires --force |
| `gpp-cpassword-hunt` | credential-access | implemented | unknown | - | - | - | no | Discover and decrypt legacy GPP cpassword secrets under SYSVOL |
| `hybrid-signals` | enumeration | implemented | unknown | - | - | - | no | Detect on-prem hybrid identity / Entra-adjacent signals (read-only) |
| `impacket-exec` | lateral-movement | implemented | unknown | - | - | - | yes | Remote execute via wmiexec / smbexec / dcomexec / atexec |
| `kerberoast` | credential-access | implemented | unknown | - | - | - | no | Request TGS tickets for SPN-enabled accounts (Kerberoasting) |
| `krb-relay` | lateral-movement | fixture-tested | live-mutating | impacket | relay-lab | - | yes | Kerberos relay / reflection into LDAP, SMB, or HTTP |
| `laps-read` | credential-access | implemented | unknown | - | - | - | no | Read LAPS v1 (ms-Mcs-AdmPwd) and v2 (msLAPS-EncryptedPassword) passwords |
| `ldap-enum` | enumeration | implemented | unknown | - | - | - | no | Enumerate users, computers, groups, trusts, SPNs, delegation, SID history, and GPO links via LDAP |
| `maq-add-computer` | privilege-escalation | fixture-tested | live-mutating | - | baseline-directory | - | yes | Create a machine account using ms-DS-MachineAccountQuota |
| `maq-rbcd-workflow` | lateral-movement | fixture-tested | live-mutating | impacket | delegated-computer | - | yes | MachineAccountQuota add-computer then RBCD then S4U |
| `next-actions` | analysis | implemented | unknown | - | - | - | no | Recommend policy-gated next actions from current graph evidence only |
| `nopac-workflow` | privilege-escalation | fixture-tested | live-mutating | impacket | unpatched-dc | - | yes | sAMAccountName spoof (noPac / CVE-2021-42278/42287) workflow |
| `ntlm-relay` | lateral-movement | implemented | unknown | - | - | - | yes | Run ntlmrelayx against a fixed allowlist; vault captured credentials |
| `password-spray` | credential-access | implemented | unknown | - | - | - | no | Lockout-aware password spray against user accounts |
| `pkinit-auth` | credential-access | implemented | unknown | - | - | - | yes | PKINIT TGT using shadow-cred key/cert from session (requires --force) |
| `pre2k-spray` | credential-access | fixture-tested | live-read-only | - | baseline-directory | - | no | Pre-Windows 2000 compatible computer accounts (password = sAMAccountName) |
| `purple-feedback` | export | implemented | unknown | - | - | - | no | Generate updated detection hypotheses from session events |
| `rbcd` | lateral-movement | implemented | unknown | - | - | - | yes | Enumerate RBCD + constrained delegation; optional set requires --force |
| `rbcd-ticket-workflow` | lateral-movement | implemented | unknown | - | - | - | yes | Set RBCD then request a service ticket when an approved provider is available |
| `report` | export | implemented | unknown | - | - | - | no | Generate operator Markdown/HTML report from current session artifacts |
| `rodc-delegation` | enumeration | implemented | unknown | - | - | - | no | Enumerate RODC password-replication policy, KRBTGT, and delegation exposure |
| `rollback` | analysis | implemented | unknown | - | - | - | yes | Reverse pending destructive changes recorded in a session (requires --force) |
| `s4u-abuse` | privilege-escalation | implemented | unknown | - | - | - | no | Full S4U2Self + S4U2Proxy chain (constrained delegation / RBCD abuse) |
| `sccm-client-push` | lateral-movement | fixture-tested | live-mutating | - | sccm-lab | - | yes | Abuse SCCM client-push installation account |
| `sccm-enum` | enumeration | fixture-tested | live-read-only | - | sccm-lab | - | no | Enumerate Microsoft Configuration Manager (SCCM/MECM) attack surface |
| `sccm-naa` | credential-access | fixture-tested | live-read-only | - | sccm-lab | - | no | Recover SCCM Network Access Account credentials |
| `sccm-takeover` | privilege-escalation | fixture-tested | live-mutating | impacket | sccm-lab | - | yes | SCCM site takeover via relay to the site database (TAKEOVER-1) |
| `secretsdump-local` | credential-access | implemented | unknown | - | - | - | no | Dump SAM/LSA/NLKM/DPAPI secrets from a host (registry / LSA, no NTDS) |
| `shadow-creds` | credential-access | implemented | unknown | - | - | - | yes | Enumerate msDS-KeyCredentialLink; optional write requires --force |
| `shadow-pkinit-workflow` | credential-access | implemented | unknown | - | - | - | yes | Write Shadow Credential then request PKINIT TGT (requires --force) |
| `sidhistory-inject` | privilege-escalation | fixture-tested | live-mutating | - | trust-lab | - | yes | Inject SID History / ExtraSids on a controlled principal |
| `sysvol-hunt` | credential-access | implemented | unknown | - | - | - | no | Search authorized SYSVOL evidence for GPP cpasswords, scripts, and tasks |
| `targeted-kerberoast` | credential-access | fixture-tested | live-mutating | impacket | delegated-acl-target | - | yes | Write SPN, Kerberoast, revert SPN |
| `template-mod` | privilege-escalation | implemented | unknown | - | - | - | yes | Flip AD CS template to ESC1-vulnerable with rollback registration |
| `ticket-forge` | credential-access | implemented | unknown | - | - | - | no | Forge golden / silver / sapphire Kerberos tickets from krbtgt / service key |
| `ticket-lifecycle` | credential-access | implemented | unknown | - | - | - | no | Inventory or import ticket/certificate artifacts into the session vault |
| `timeroast` | credential-access | fixture-tested | live-read-only | - | baseline-directory | - | no | Unauthenticated RID roast via NTP (Timeroasting) |
| `trustedtoauth` | lateral-movement | fixture-tested | live-read-only | impacket | delegated-service | - | no | Protocol-transition constrained delegation (TrustedToAuthForDelegation) |
| `trusts-enum` | enumeration | implemented | unknown | - | - | - | no | Deep trust enumeration with SID-filtering attack-path analysis |
| `unconst-tgtdump-workflow` | credential-access | fixture-tested | live-mutating | impacket | unconstrained-computer | - | yes | Unconstrained-delegation hunt then coerce to capture a TGT |
| `unconstrained-delegation` | enumeration | fixture-tested | live-read-only | - | baseline-directory | - | no | Hunt computers trusted for unconstrained delegation (TGT delegation) |
| `unpac-the-hash` | credential-access | implemented | unknown | - | - | - | no | Recover NT hash from a PKINIT-only cert by parsing PAC_CREDENTIAL_INFO |
| `write-spn` | credential-access | fixture-tested | live-mutating | - | delegated-acl-target | - | yes | Set or clear servicePrincipalName for targeted Kerberoast |
