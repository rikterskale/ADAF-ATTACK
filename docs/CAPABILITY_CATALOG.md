# Capability catalog

This document is regenerated from the running package by
`scripts/generate_capability_catalog.py`. Do not edit by hand; run the
script (CI enforces parity).

| ID | Category | Maturity | Environment | Tools | Fixture | Difficulty | Risk | Approval | Rollback | Summary |
|----|----------|----------|-------------|-------|---------|------------|------|----------|----------|---------|
| `aadconnect-dcsync` | credential-access | fixture-tested | live-read-only | impacket | hybrid-lab | - | observe | none | none | Identify and use Azure AD Connect MSOL_* replication rights |
| `acl-abuse` | privilege-escalation | fixture-tested | live-mutating | - | delegated-acl-target | - | destructive | force_and_ack | manual | Operator ACL abuse: GenericAll / GenericWrite / WriteDacl / WriteOwner / Owns |
| `acl-enum` | enumeration | implemented | unknown | - | - | - | observe | none | none | Enumerate interesting ACL edges (high-value or domain-wide scope) |
| `acl-write` | privilege-escalation | implemented | unknown | - | - | - | destructive | force_and_ack | manual | Apply an approved raw ACL descriptor with rollback capture |
| `ad-cve-scan` | enumeration | implemented | unknown | - | - | - | observe | none | none | Non-exploiting scan for Zerologon / noPAC / Certifried / signing posture |
| `adcs-enum` | enumeration | implemented | unknown | - | - | - | observe | none | none | Enumerate AD CS CAs/templates, ESC1-ESC9 signals, and enrollment rights |
| `adcs-policy-probe` | enumeration | implemented | unknown | - | - | - | observe | none | none | Evaluate CA/DC policy evidence for ESC10-ESC15 |
| `add-member` | privilege-escalation | fixture-tested | live-mutating | - | delegated-acl-target | - | destructive | force_and_ack | manual | Add a principal to a group (AddMember / GenericAll on group) |
| `add-self` | privilege-escalation | fixture-tested | live-mutating | - | delegated-acl-target | - | destructive | force_and_ack | manual | Add the current principal to a group (AddSelf) |
| `adidns-wpad` | lateral-movement | fixture-tested | live-mutating | - | dns-lab | - | destructive | force_and_ack | manual | Plant WPAD / wildcard records in AD-integrated DNS |
| `adminsdholder-persist` | persistence | fixture-tested | live-mutating | - | domain-admin-lab | - | destructive | force_and_ack | manual | Plant a persistence ACE on AdminSDHolder |
| `asrep-roast` | credential-access | implemented | unknown | - | - | - | observe | none | none | Identify and roast accounts that do not require pre-authentication |
| `asreq-userhunt` | enumeration | implemented | unknown | - | - | - | observe | none | none | Validate usernames via Kerberos AS-REQ without incrementing badPwdCount |
| `attack-paths` | analysis | implemented | unknown | - | - | - | observe | none | none | Rank weighted attack paths from principals toward high-value targets |
| `azureadssoacc-roast` | credential-access | fixture-tested | live-read-only | impacket | hybrid-lab | - | observe | none | none | Kerberoast the Seamless SSO computer account (AZUREADSSOACC$) |
| `badsuccessor` | privilege-escalation | fixture-tested | live-mutating | - | dmsa-lab | - | destructive | force_and_ack | manual | Windows Server 2025 dMSA BadSuccessor privilege escalation |
| `blast-radius` | analysis | implemented | unknown | - | - | - | observe | none | none | Calculate reachable high-value impact from a graph principal |
| `bloodhound-export` | export | implemented | unknown | - | - | - | observe | none | none | Export attack graph to BloodHound CE JSON + ingest zip |
| `bloodhound-import` | export | implemented | unknown | - | - | - | observe | none | none | Import BloodHound-compatible JSON, enrich locally, and re-export |
| `campaign-run` | analysis | implemented | unknown | - | - | - | destructive | force_and_ack | manual | Run ordered engagement phases with vault hand-off and purple package |
| `cert-request` | credential-access | implemented | unknown | - | - | - | destructive | force_and_ack | manual | Request a certificate from AD CS (ESC1 enroll path); requires --force |
| `coerce` | credential-access | implemented | unknown | - | - | - | side_effect | scoped_token | none | Trigger coercion only against an approved host allowlist |
| `coercion-map` | discovery | implemented | unknown | - | - | - | observe | none | none | Map coercion surfaces (Spooler/EFSRPC) on domain computers — detect only |
| `computer-takeover` | enumeration | implemented | unknown | - | - | - | observe | none | none | Identify writable computer SPN and DNS identity surfaces |
| `constrained-delegation` | lateral-movement | fixture-tested | live-mutating | impacket | delegated-service | - | destructive | force_and_ack | manual | Abuse constrained delegation (msDS-AllowedToDelegateTo) |
| `credential-inventory` | credential-access | implemented | unknown | - | - | - | observe | none | none | Inventory, export, purge, or mark-for-rotation session credential material |
| `dcshadow` | persistence | fixture-tested | live-mutating | impacket | disposable-dc | - | destructive | force_and_ack | manual | DCShadow replication-based directory modification |
| `dcsync` | credential-access | implemented | unknown | - | - | - | side_effect | force_and_ack | none | Replicate NT/LM/aes secrets via MS-DRSR (DCSync) |
| `dcsync-grant-workflow` | credential-access | fixture-tested | live-mutating | impacket | delegated-acl-target | - | destructive | force_and_ack | manual | Grant DS-Replication rights, DCSync, revert the ACE |
| `dmsa-ouroboros` | credential-access | fixture-tested | live-mutating | - | dmsa-lab | - | destructive | force_and_ack | manual | Post-patch dMSA Ouroboros credential extraction (Server 2025) |
| `dnsadmin-srv` | privilege-escalation | fixture-tested | live-mutating | - | dns-lab | - | destructive | force_and_ack | manual | DNSAdmins name-abuse (SRV / WPAD) without a server DLL drop |
| `dpapi-domain-backup` | credential-access | fixture-tested | live-read-only | impacket | delegated-replication | - | observe | none | none | Retrieve the domain DPAPI backup key via replication rights |
| `esc-chain` | privilege-escalation | implemented | unknown | - | - | - | destructive | force_and_ack | manual | Automated ESC1-ESC15 exploit chain: template -> cert -> PKINIT -> TGT |
| `esc10` | adcs | fixture-tested | live-mutating | certipy | adcs-lab | - | destructive | force_and_ack | manual | AD CS ESC10: weak certificate mapping |
| `esc13` | adcs | fixture-tested | live-mutating | certipy | adcs-lab | - | destructive | force_and_ack | manual | AD CS ESC13: issuance policy linked to a privileged group |
| `esc14` | adcs | fixture-tested | live-mutating | certipy | adcs-lab | - | destructive | force_and_ack | manual | AD CS ESC14: weak explicit certificate mapping |
| `esc15` | adcs | fixture-tested | live-mutating | certipy | adcs-lab | - | destructive | force_and_ack | manual | AD CS ESC15 (EKUwu / CVE-2024-49019): v1 template application policy override |
| `esc16` | adcs | fixture-tested | live-mutating | certipy | adcs-lab | - | destructive | force_and_ack | manual | AD CS ESC16: security extension disabled on the CA |
| `esc8-relay-workflow` | adcs | fixture-tested | live-mutating | impacket, certipy | adcs-lab | - | destructive | force_and_ack | manual | Coerce plus HTTP relay to AD CS web enrollment (ESC8) |
| `esc9` | adcs | fixture-tested | live-mutating | certipy | adcs-lab | - | destructive | force_and_ack | manual | AD CS ESC9: template with no SID security extension |
| `force-change-password` | credential-access | fixture-tested | live-mutating | - | delegated-acl-target | - | destructive | force_and_ack | manual | Reset a user password via User-Force-Change-Password |
| `gmsa-laps-enum` | credential-access | implemented | unknown | - | - | - | observe | none | none | Enumerate gMSAs and LAPS; read secrets with --include-secrets when permitted |
| `gmsa-read` | credential-access | fixture-tested | live-read-only | - | gmsa-laps | - | observe | none | none | Read and parse msDS-ManagedPassword for a gMSA |
| `golden-cert` | persistence | fixture-tested | live-mutating | certipy | adcs-lab | - | destructive | force_and_ack | manual | Forge authentication certificates from a stolen CA key |
| `gpo-abuse` | privilege-escalation | implemented | unknown | - | - | - | observe | none | none | Enumerate writable GPOs with link-based blast-radius ranking |
| `gpo-link` | privilege-escalation | implemented | unknown | - | - | - | destructive | force_and_ack | manual | Replace an approved GPO link with rollback capture |
| `gpo-sysvol` | privilege-escalation | implemented | unknown | - | - | - | observe | none | none | Probe SYSVOL GPO paths for write; optional stage requires --force |
| `gpp-cpassword-hunt` | credential-access | implemented | unknown | - | - | - | observe | none | none | Discover and decrypt legacy GPP cpassword secrets under SYSVOL |
| `hybrid-signals` | enumeration | implemented | unknown | - | - | - | observe | none | none | Detect on-prem hybrid identity / Entra-adjacent signals (read-only) |
| `impacket-exec` | lateral-movement | implemented | unknown | - | - | - | destructive | scoped_token | manual | Scoped remote execute via wmiexec / smbexec / dcomexec / atexec with execution status |
| `kerberoast` | credential-access | implemented | unknown | - | - | - | observe | none | none | Request TGS tickets for SPN-enabled accounts (Kerberoasting) |
| `krb-relay` | lateral-movement | fixture-tested | live-mutating | impacket | relay-lab | - | destructive | force_and_ack | manual | Kerberos relay / reflection into LDAP, SMB, or HTTP |
| `laps-read` | credential-access | implemented | unknown | - | - | - | observe | none | none | Read LAPS v1 (ms-Mcs-AdmPwd) and v2 (msLAPS-EncryptedPassword) passwords |
| `ldap-enum` | enumeration | implemented | unknown | - | - | - | observe | none | none | Enumerate users, computers, groups, trusts, SPNs, delegation, SID history, and GPO links via LDAP |
| `maq-add-computer` | privilege-escalation | fixture-tested | live-mutating | - | baseline-directory | - | destructive | force_and_ack | manual | Create a machine account using ms-DS-MachineAccountQuota |
| `maq-rbcd-workflow` | lateral-movement | fixture-tested | live-mutating | impacket | delegated-computer | - | destructive | force_and_ack | manual | MachineAccountQuota add-computer then RBCD then S4U |
| `next-actions` | analysis | implemented | unknown | - | - | - | observe | none | none | Recommend policy-gated next actions from current graph evidence only |
| `nopac-workflow` | privilege-escalation | fixture-tested | live-mutating | impacket | unpatched-dc | - | destructive | force_and_ack | manual | sAMAccountName spoof (noPac / CVE-2021-42278/42287) workflow |
| `ntlm-relay` | lateral-movement | implemented | unknown | - | - | - | destructive | force_and_ack | manual | Run ntlmrelayx against a fixed allowlist; vault captured credentials |
| `password-spray` | credential-access | implemented | unknown | - | - | - | side_effect | scoped_token | none | Lockout-aware password spray against user accounts |
| `pkinit-auth` | credential-access | implemented | unknown | - | - | - | destructive | force_and_ack | manual | PKINIT TGT using shadow-cred key/cert from session (requires --force) |
| `pre2k-spray` | credential-access | fixture-tested | live-read-only | - | baseline-directory | - | observe | none | none | Pre-Windows 2000 compatible computer accounts (password = sAMAccountName) |
| `purple-feedback` | export | implemented | unknown | - | - | - | observe | none | none | Generate updated detection hypotheses from session events |
| `rbcd` | lateral-movement | implemented | unknown | - | - | - | observe | none | none | Enumerate RBCD + constrained delegation; optional set requires --force |
| `rbcd-ticket-workflow` | lateral-movement | implemented | unknown | - | - | - | destructive | force_and_ack | manual | Set RBCD then request a service ticket when an approved provider is available |
| `report` | export | implemented | unknown | - | - | - | observe | none | none | Generate operator Markdown/HTML report from current session artifacts |
| `rodc-delegation` | enumeration | implemented | unknown | - | - | - | observe | none | none | Enumerate RODC password-replication policy, KRBTGT, and delegation exposure |
| `rollback` | analysis | implemented | unknown | - | - | - | destructive | force_and_ack | manual | Reverse pending destructive changes recorded in a session (requires --force) |
| `s4u-abuse` | privilege-escalation | implemented | unknown | - | - | - | side_effect | force_and_ack | none | Full S4U2Self + S4U2Proxy chain (constrained delegation / RBCD abuse) |
| `sccm-client-push` | lateral-movement | fixture-tested | live-mutating | - | sccm-lab | - | destructive | force_and_ack | manual | Abuse SCCM client-push installation account |
| `sccm-enum` | enumeration | fixture-tested | live-read-only | - | sccm-lab | - | observe | none | none | Enumerate Microsoft Configuration Manager (SCCM/MECM) attack surface |
| `sccm-naa` | credential-access | fixture-tested | live-read-only | - | sccm-lab | - | observe | none | none | Recover SCCM Network Access Account credentials |
| `sccm-takeover` | privilege-escalation | fixture-tested | live-mutating | impacket | sccm-lab | - | destructive | force_and_ack | manual | SCCM site takeover via relay to the site database (TAKEOVER-1) |
| `secretsdump-local` | credential-access | implemented | unknown | - | - | - | observe | none | none | Dump SAM/LSA/NLKM/DPAPI secrets from a host (registry / LSA, no NTDS) |
| `shadow-creds` | credential-access | implemented | unknown | - | - | - | observe | none | none | Enumerate msDS-KeyCredentialLink; optional write requires --force |
| `shadow-pkinit-workflow` | credential-access | implemented | unknown | - | - | - | destructive | force_and_ack | manual | Write Shadow Credential then request PKINIT TGT (requires --force) |
| `sidhistory-inject` | privilege-escalation | fixture-tested | live-mutating | - | trust-lab | - | destructive | force_and_ack | manual | Inject SID History / ExtraSids on a controlled principal |
| `sysvol-hunt` | credential-access | implemented | unknown | - | - | - | observe | none | none | Search authorized SYSVOL evidence for GPP cpasswords, scripts, and tasks |
| `targeted-kerberoast` | credential-access | fixture-tested | live-mutating | impacket | delegated-acl-target | - | destructive | force_and_ack | manual | Write SPN, Kerberoast, revert SPN |
| `template-mod` | privilege-escalation | implemented | unknown | - | - | - | destructive | force_and_ack | manual | Flip AD CS template to ESC1-vulnerable with rollback registration |
| `ticket-forge` | credential-access | implemented | unknown | - | - | - | observe | none | none | Forge golden / silver / sapphire Kerberos tickets from krbtgt / service key |
| `ticket-lifecycle` | credential-access | implemented | unknown | - | - | - | observe | none | none | Inventory or import ticket/certificate artifacts into the session vault |
| `timeroast` | credential-access | fixture-tested | live-read-only | - | baseline-directory | - | observe | none | none | Unauthenticated RID roast via NTP (Timeroasting) |
| `trustedtoauth` | lateral-movement | fixture-tested | live-read-only | impacket | delegated-service | - | observe | none | none | Protocol-transition constrained delegation (TrustedToAuthForDelegation) |
| `trusts-enum` | enumeration | implemented | unknown | - | - | - | observe | none | none | Deep trust enumeration with SID-filtering attack-path analysis |
| `unconst-tgtdump-workflow` | credential-access | fixture-tested | live-mutating | impacket | unconstrained-computer | - | destructive | force_and_ack | manual | Unconstrained-delegation hunt then coerce to capture a TGT |
| `unconstrained-delegation` | enumeration | fixture-tested | live-read-only | - | baseline-directory | - | observe | none | none | Hunt computers trusted for unconstrained delegation (TGT delegation) |
| `unpac-the-hash` | credential-access | implemented | unknown | - | - | - | observe | none | none | Inspect PAC_CREDENTIAL_INFO from a PKINIT-only cert without claiming hash recovery |
| `write-spn` | credential-access | fixture-tested | live-mutating | - | delegated-acl-target | - | destructive | force_and_ack | manual | Set or clear servicePrincipalName for targeted Kerberoast |
