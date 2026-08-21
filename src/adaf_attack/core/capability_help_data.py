"""Per-capability option requirements exposed by `capability-help`.

Kept as a small maintained mapping rather than reflection on runner
signatures: the runners use `**kwargs` and there is no single source of
truth for which extras a given capability requires.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class OptionSpec:
    required: tuple[str, ...]
    optional: tuple[str, ...] = ()
    notes: str | None = None


_UNIVERSAL_REQUIRED = ("--domain", "--dc-ip")
_UNIVERSAL_OPTIONAL = (
    "--username",
    "--password",
    "--hashes",
    "--aes-key",
    "--ccache",
    "--kerberos",
    "--ldaps",
    "--workspace",
    "--creds-file",
)

# Offline / analysis capabilities do not need domain/dc-ip.
_OFFLINE_REQUIRED: tuple[str, ...] = ()
_OFFLINE_OPTIONAL = ("--workspace",)

_SPEC: dict[str, OptionSpec] = {
    # Enumeration — universal-only
    "ldap-enum": OptionSpec(_UNIVERSAL_REQUIRED, _UNIVERSAL_OPTIONAL),
    "trusts-enum": OptionSpec(_UNIVERSAL_REQUIRED, _UNIVERSAL_OPTIONAL),
    "adcs-enum": OptionSpec(_UNIVERSAL_REQUIRED, _UNIVERSAL_OPTIONAL),
    "adcs-policy-probe": OptionSpec(_UNIVERSAL_REQUIRED, _UNIVERSAL_OPTIONAL),
    "acl-enum": OptionSpec(_UNIVERSAL_REQUIRED, _UNIVERSAL_OPTIONAL + ("--scope", "--max-objects")),
    "gmsa-laps-enum": OptionSpec(_UNIVERSAL_REQUIRED, _UNIVERSAL_OPTIONAL),
    "kerberoast": OptionSpec(_UNIVERSAL_REQUIRED, _UNIVERSAL_OPTIONAL),
    "asrep-roast": OptionSpec(_UNIVERSAL_REQUIRED, _UNIVERSAL_OPTIONAL),
    "sysvol-hunt": OptionSpec(_UNIVERSAL_REQUIRED, _UNIVERSAL_OPTIONAL),
    "coercion-map": OptionSpec(_UNIVERSAL_REQUIRED, _UNIVERSAL_OPTIONAL),
    "gpo-link": OptionSpec(_UNIVERSAL_REQUIRED, _UNIVERSAL_OPTIONAL),
    "identity-bridge": OptionSpec(_UNIVERSAL_REQUIRED, _UNIVERSAL_OPTIONAL),
    "rodc-delegation": OptionSpec(_UNIVERSAL_REQUIRED, _UNIVERSAL_OPTIONAL),
    # Certificate operations
    "cert-request": OptionSpec(
        _UNIVERSAL_REQUIRED + ("--template", "--ca"),
        _UNIVERSAL_OPTIONAL + ("--alt-name",),
    ),
    "pkinit-auth": OptionSpec(
        _UNIVERSAL_REQUIRED + ("--sam",),
        _UNIVERSAL_OPTIONAL + ("--key", "--cert", "--pfx"),
    ),
    # Destructive writes
    "acl-write": OptionSpec(
        _UNIVERSAL_REQUIRED + ("--write-target", "--descriptor-hex", "--force"),
        _UNIVERSAL_OPTIONAL,
    ),
    "shadow-creds": OptionSpec(
        _UNIVERSAL_REQUIRED + ("--sam", "--force"),
        _UNIVERSAL_OPTIONAL + ("--attribute", "--value"),
        notes="Destructive; --force required.",
    ),
    "rbcd": OptionSpec(
        _UNIVERSAL_REQUIRED + ("--set-on", "--set-from", "--force"),
        _UNIVERSAL_OPTIONAL,
        notes="Destructive; --force required.",
    ),
    "gpo-abuse": OptionSpec(
        _UNIVERSAL_REQUIRED + ("--gpo", "--payload", "--force"),
        _UNIVERSAL_OPTIONAL,
        notes="Destructive; --force required. --payload accepts @path or inline text.",
    ),
    "gpo-sysvol": OptionSpec(
        _UNIVERSAL_REQUIRED + ("--gpo", "--payload", "--force"),
        _UNIVERSAL_OPTIONAL,
        notes="Destructive; --force required.",
    ),
    "computer-takeover": OptionSpec(
        _UNIVERSAL_REQUIRED + ("--sam", "--force"),
        _UNIVERSAL_OPTIONAL,
        notes="Destructive; --force required.",
    ),
    "ticket-lifecycle": OptionSpec(
        _UNIVERSAL_REQUIRED + ("--operation",),
        _UNIVERSAL_OPTIONAL + ("--artifact",),
    ),
    # Offline analysis
    "attack-paths": OptionSpec(
        _OFFLINE_REQUIRED,
        _OFFLINE_OPTIONAL + ("--graph", "--start", "--max-depth", "--limit"),
    ),
    "blast-radius": OptionSpec(
        _OFFLINE_REQUIRED,
        _OFFLINE_OPTIONAL + ("--graph", "--start"),
    ),
    "campaign-analysis": OptionSpec(_OFFLINE_REQUIRED, _OFFLINE_OPTIONAL + ("--graph",)),
    "bloodhound-export": OptionSpec(_UNIVERSAL_REQUIRED, _UNIVERSAL_OPTIONAL),
    "next-actions": OptionSpec(_OFFLINE_REQUIRED, _OFFLINE_OPTIONAL + ("--graph",)),
    "report": OptionSpec(_OFFLINE_REQUIRED, _OFFLINE_OPTIONAL),
    # Workflow helpers
    "shadow-pkinit-workflow": OptionSpec(
        _UNIVERSAL_REQUIRED + ("--sam", "--force"),
        _UNIVERSAL_OPTIONAL,
        notes="Joined write + PKINIT; --force required.",
    ),
    "rbcd-ticket-workflow": OptionSpec(
        _UNIVERSAL_REQUIRED + ("--set-on", "--set-from", "--spn", "--impersonate", "--force"),
        _UNIVERSAL_OPTIONAL,
        notes="Joined RBCD + S4U ticket handoff; --force required.",
    ),
    # 15 offensive-capability additions
    "dcsync": OptionSpec(
        _UNIVERSAL_REQUIRED,
        _UNIVERSAL_OPTIONAL + ("-P sam=<user>", "-P history=true", "-P principals=<path>"),
        notes="Requires replicating-changes-all rights (or DA).",
    ),
    "password-spray": OptionSpec(
        _UNIVERSAL_REQUIRED + ("-P spray_password=<candidate>",),
        _UNIVERSAL_OPTIONAL
        + (
            "-P users=<path-or-ldap-filter>",
            "-P safety_margin=2",
            "-P delay_seconds=0",
            "-P max_attempts=0",
        ),
        notes="Refuses accounts within safety_margin of lockoutThreshold.",
    ),
    "laps-read": OptionSpec(
        _UNIVERSAL_REQUIRED,
        _UNIVERSAL_OPTIONAL + ("-P computer_filter=<ldap-filter>",),
        notes="Reads v1 ms-Mcs-AdmPwd + v2 msLAPS-EncryptedPassword blob.",
    ),
    "gpp-cpassword-hunt": OptionSpec(
        ("-P sysvol=<mounted-sysvol-path>",),
        (),
        notes="Pure-offline SYSVOL scan; no LDAP required.",
    ),
    "unpac-the-hash": OptionSpec(
        _UNIVERSAL_REQUIRED + ("-P sam=<user>",),
        _UNIVERSAL_OPTIONAL + ("-P pfx=<path>", "-P key=<pem>", "-P cert=<pem>"),
        notes="Cert -> PKINIT -> PAC parse; NT hash recovery on modern KDCs.",
    ),
    "ticket-forge": OptionSpec(
        (
            "-P variant=golden|silver|sapphire",
            "-P impersonate=<user>",
            "-P domain_sid=<S-1-5-21-...>",
        ),
        (
            "-P nt=<krbtgt-nt-hash>",
            "-P aes=<aes256-hex>",
            "-P spn=<service/host@domain>",
            "-P groups=<rid1,rid2>",
            "-P extra_sid=<S-1-5-...>",
        ),
        notes="Silver requires spn; sapphire uses extended PAC.",
    ),
    "s4u-abuse": OptionSpec(
        _UNIVERSAL_REQUIRED + ("-P impersonate=<user>", "-P spn=<service/host>"),
        _UNIVERSAL_OPTIONAL
        + (
            "-P additional_ticket=<ccache>",
            "-P altservice=<name>",
            "-P self_flag=true",
            "-P u2u=true",
        ),
        notes="S4U2Self + S4U2Proxy chain; RBCD via --additional-ticket.",
    ),
    "asreq-userhunt": OptionSpec(
        _UNIVERSAL_REQUIRED + ("-P users=<path-to-user-list>",),
        (),
        notes="Does not increment badPwdCount; detects AS-REP roastable users.",
    ),
    "coerce": OptionSpec(
        _UNIVERSAL_REQUIRED + ("-P listener=<attacker-ip>",),
        _UNIVERSAL_OPTIONAL
        + (
            "-P host=<target-ip>",
            "-P methods=petitpotam,printerbug,dfscoerce,shadowcoerce",
        ),
    ),
    "ntlm-relay": OptionSpec(
        _UNIVERSAL_REQUIRED + ("-P relay_targets=<host1,host2>", "--force"),
        _UNIVERSAL_OPTIONAL
        + (
            "-P listen_port=445",
            "-P duration_seconds=60",
            "-P extras='--http-port 80 -c whoami'",
        ),
        notes="Destructive: writes to relayed services. Requires --force.",
    ),
    "esc-chain": OptionSpec(
        _UNIVERSAL_REQUIRED,
        _UNIVERSAL_OPTIONAL
        + (
            "-P adcs_session=<prior-session-dir>",
            "-P template=<name>",
            "-P ca=<name>",
            "-P sam=<user>",
            "-P alt_name=<upn-or-dns>",
        ),
        notes="Orchestrates cert-request + pkinit-auth end-to-end.",
    ),
    "template-mod": OptionSpec(
        _UNIVERSAL_REQUIRED + ("-P template=<name>", "--force"),
        _UNIVERSAL_OPTIONAL,
        notes="Destructive: modifies template DACL/EKU flags. Rollback via cleanup.",
    ),
    "secretsdump-local": OptionSpec(
        _UNIVERSAL_REQUIRED,
        _UNIVERSAL_OPTIONAL + ("-P host=<target>",),
        notes="Dumps SAM/LSA/DPAPI via remote registry over SMB.",
    ),
    "impacket-exec": OptionSpec(
        _UNIVERSAL_REQUIRED
        + (
            "-P method=wmiexec|smbexec|dcomexec|atexec",
            "-P command=<cmd>",
            "--force",
        ),
        _UNIVERSAL_OPTIONAL + ("-P host=<target>", "-P share=C$"),
        notes="Destructive: creates services/processes on the host.",
    ),
    "ad-cve-scan": OptionSpec(
        _UNIVERSAL_REQUIRED,
        _UNIVERSAL_OPTIONAL,
        notes="Read-only posture assessment; produces ad-cve-scan.json.",
    ),
    "add-member": OptionSpec(
        _UNIVERSAL_REQUIRED + ("-P group=<sam>", "-P member=<sam>", "--force"),
        _UNIVERSAL_OPTIONAL,
        notes="Destructive; --force required.",
    ),
    "add-self": OptionSpec(
        _UNIVERSAL_REQUIRED + ("-P group=<sam>", "--force"),
        _UNIVERSAL_OPTIONAL,
        notes="Adds --username to the group. Destructive; --force required.",
    ),
    "force-change-password": OptionSpec(
        _UNIVERSAL_REQUIRED + ("-P sam=<user>", "-P new_password=<pwd>", "--force"),
        _UNIVERSAL_OPTIONAL,
        notes="Requires LDAPS for unicodePwd. Previous password is not recoverable.",
    ),
    "acl-abuse": OptionSpec(
        _UNIVERSAL_REQUIRED + ("-P sam=<target>", "--force"),
        _UNIVERSAL_OPTIONAL + ("-P rights=GenericAll|WriteDacl|WriteOwner|GetChangesAll",),
        notes="Writes nTSecurityDescriptor; rollback restores the prior SD.",
    ),
    "write-spn": OptionSpec(
        _UNIVERSAL_REQUIRED + ("-P sam=<user>", "--force"),
        _UNIVERSAL_OPTIONAL + ("-P spn=<service/host>", "-P clear=true"),
        notes="Destructive; --force required.",
    ),
    "unconstrained-delegation": OptionSpec(_UNIVERSAL_REQUIRED, _UNIVERSAL_OPTIONAL),
    "constrained-delegation": OptionSpec(
        _UNIVERSAL_REQUIRED,
        _UNIVERSAL_OPTIONAL + ("-P sam=<account>", "-P spn=<service/host>", "--force"),
        notes="Enum is read-only; set path requires --force.",
    ),
    "trustedtoauth": OptionSpec(_UNIVERSAL_REQUIRED, _UNIVERSAL_OPTIONAL),
    "badsuccessor": OptionSpec(
        _UNIVERSAL_REQUIRED + ("-P preceded_by=<sam>", "--force"),
        _UNIVERSAL_OPTIONAL + ("-P name=<dmsa>",),
        notes="Creates a dMSA linked to preceded_by. Destructive; --force required.",
    ),
    "dmsa-ouroboros": OptionSpec(
        _UNIVERSAL_REQUIRED + ("--force",),
        _UNIVERSAL_OPTIONAL + ("-P sam=<dmsa>", "-P preceded_by=<sam>"),
        notes="Reads or creates a dMSA and attempts msDS-ManagedPassword recovery.",
    ),
    "esc9": OptionSpec(
        _UNIVERSAL_REQUIRED + ("--force",),
        _UNIVERSAL_OPTIONAL + ("-P template=<name>", "-P ca=<name>", "-P alt_name=<upn>"),
    ),
    "esc10": OptionSpec(
        _UNIVERSAL_REQUIRED + ("--force",),
        _UNIVERSAL_OPTIONAL + ("-P template=<name>", "-P ca=<name>", "-P alt_name=<upn>"),
    ),
    "esc13": OptionSpec(
        _UNIVERSAL_REQUIRED + ("--force",),
        _UNIVERSAL_OPTIONAL + ("-P template=<name>", "-P ca=<name>", "-P alt_name=<upn>"),
    ),
    "esc14": OptionSpec(
        _UNIVERSAL_REQUIRED + ("--force",),
        _UNIVERSAL_OPTIONAL + ("-P template=<name>", "-P ca=<name>", "-P alt_name=<upn>"),
    ),
    "esc15": OptionSpec(
        _UNIVERSAL_REQUIRED + ("--force",),
        _UNIVERSAL_OPTIONAL + ("-P template=<name>", "-P ca=<name>", "-P alt_name=<upn>"),
    ),
    "esc16": OptionSpec(
        _UNIVERSAL_REQUIRED + ("--force",),
        _UNIVERSAL_OPTIONAL + ("-P template=<name>", "-P ca=<name>", "-P alt_name=<upn>"),
    ),
    "golden-cert": OptionSpec(
        _UNIVERSAL_REQUIRED + ("-P ca_pfx=<stolen-ca.pfx>", "-P upn=<user@domain>", "--force"),
        _UNIVERSAL_OPTIONAL,
    ),
    "esc8-relay-workflow": OptionSpec(
        _UNIVERSAL_REQUIRED + ("-P ca=<web-enrollment-host>", "--force"),
        _UNIVERSAL_OPTIONAL + ("-P coerce_host=<host>", "-P listener=<ip>"),
    ),
    "krb-relay": OptionSpec(
        _UNIVERSAL_REQUIRED + ("-P relay_targets=<ldap://host>", "--force"),
        _UNIVERSAL_OPTIONAL + ("-P duration_seconds=60",),
    ),
    "maq-add-computer": OptionSpec(
        _UNIVERSAL_REQUIRED + ("--force",),
        _UNIVERSAL_OPTIONAL + ("-P computer=<name>", "-P password=<pwd>"),
    ),
    "maq-rbcd-workflow": OptionSpec(
        _UNIVERSAL_REQUIRED + ("-P set_on=<computer>", "--force"),
        _UNIVERSAL_OPTIONAL + ("-P impersonate=<user>", "-P spn=<service/host>"),
    ),
    "targeted-kerberoast": OptionSpec(
        _UNIVERSAL_REQUIRED + ("-P sam=<user>", "--force"),
        _UNIVERSAL_OPTIONAL + ("-P spn=<service/host>",),
    ),
    "dcsync-grant-workflow": OptionSpec(
        _UNIVERSAL_REQUIRED + ("--force",),
        _UNIVERSAL_OPTIONAL + ("-P principal_sid=<SID>", "-P dcsync_sam=krbtgt"),
    ),
    "nopac-workflow": OptionSpec(
        _UNIVERSAL_REQUIRED + ("-P dc=<DC$>", "--force"),
        _UNIVERSAL_OPTIONAL + ("-P name=<machine>",),
    ),
    "unconst-tgtdump-workflow": OptionSpec(
        _UNIVERSAL_REQUIRED + ("--force",),
        _UNIVERSAL_OPTIONAL + ("-P host=<unconstrained>", "-P listener=<ip>"),
    ),
    "adminsdholder-persist": OptionSpec(
        _UNIVERSAL_REQUIRED + ("--force",),
        _UNIVERSAL_OPTIONAL + ("-P principal_sid=<SID>",),
    ),
    "sidhistory-inject": OptionSpec(
        _UNIVERSAL_REQUIRED + ("-P sam=<user>", "-P sid=<S-1-5-...>", "--force"),
        _UNIVERSAL_OPTIONAL,
    ),
    "pre2k-spray": OptionSpec(
        _UNIVERSAL_REQUIRED,
        _UNIVERSAL_OPTIONAL + ("-P max_attempts=50",),
    ),
    "timeroast": OptionSpec(
        _UNIVERSAL_REQUIRED,
        _UNIVERSAL_OPTIONAL + ("-P rid_start=1000", "-P rid_end=1032"),
    ),
    "gmsa-read": OptionSpec(
        _UNIVERSAL_REQUIRED,
        _UNIVERSAL_OPTIONAL + ("-P sam=<gmsa>",),
        notes="Use --include-secrets to return current gMSA password material.",
    ),
    "dcshadow": OptionSpec(
        _UNIVERSAL_REQUIRED + ("-P computer=<sam>", "--force"),
        _UNIVERSAL_OPTIONAL + ("-P site=Default-First-Site-Name",),
    ),
    "adidns-wpad": OptionSpec(
        _UNIVERSAL_REQUIRED + ("-P ip=<attacker-ip>", "--force"),
        _UNIVERSAL_OPTIONAL + ("-P name=wpad", "-P cname=<host>"),
    ),
    "dnsadmin-srv": OptionSpec(
        _UNIVERSAL_REQUIRED + ("-P host=<attacker-fqdn>", "--force"),
        _UNIVERSAL_OPTIONAL + ("-P name=_ldap._tcp", "-P port=389"),
    ),
    "sccm-enum": OptionSpec(_UNIVERSAL_REQUIRED, _UNIVERSAL_OPTIONAL),
    "sccm-naa": OptionSpec(
        _UNIVERSAL_REQUIRED,
        _UNIVERSAL_OPTIONAL + ("-P mp=<management-point>",),
    ),
    "sccm-takeover": OptionSpec(
        _UNIVERSAL_REQUIRED + ("-P site_db=<sql-host>", "--force"),
        _UNIVERSAL_OPTIONAL,
    ),
    "sccm-client-push": OptionSpec(
        _UNIVERSAL_REQUIRED + ("-P host=<target>", "--force"),
        _UNIVERSAL_OPTIONAL + ("-P site_code=P01",),
    ),
    "azureadssoacc-roast": OptionSpec(_UNIVERSAL_REQUIRED, _UNIVERSAL_OPTIONAL),
    "aadconnect-dcsync": OptionSpec(
        _UNIVERSAL_REQUIRED,
        _UNIVERSAL_OPTIONAL + ("-P sam=MSOL_...",),
    ),
    "dpapi-domain-backup": OptionSpec(_UNIVERSAL_REQUIRED, _UNIVERSAL_OPTIONAL),
}


def capability_option_spec(capability_id: str, destructive: bool) -> OptionSpec:
    """Return the option spec for a capability, with a safe universal default."""
    spec = _SPEC.get(capability_id)
    if spec:
        return spec
    required = _UNIVERSAL_REQUIRED + (("--force",) if destructive else ())
    return OptionSpec(required, _UNIVERSAL_OPTIONAL)
