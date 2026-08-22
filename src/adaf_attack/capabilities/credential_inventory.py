"""Credential material inventory with safe export, purge, and rotation markers.

Catalogs everything the session currently holds:
  - Encrypted vault items (password, NT hash, AES keys, TGTs, KeyCreds, gMSA, …)
  - Loose session artifacts (*.ccache, *.pfx, shadow-*.pem, …)

Destructive actions (purge) require --force. Secrets are never printed unless
--include-secrets is set and the vault key is available.
"""

from __future__ import annotations

import json
import shutil
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.table import Table

from adaf_attack.core.graph import AttackGraph
from adaf_attack.core.registry import register_capability
from adaf_attack.core.session import Session
from adaf_attack.core.target import Target
from adaf_attack.core.vault import VaultError

console = Console()

ARTIFACT_GLOBS = (
    "*.ccache",
    "*.pfx",
    "*.pem",
    "shadow-*.dnbinary.txt",
    "imported-*",
    "exported.*",
    "relay-artifacts/*",
)

KIND_LABELS = {
    "ccache": "Kerberos TGT/TGS ccache",
    "pfx": "Certificate (PFX)",
    "pem": "PEM key/cert material",
    "ntlm-hash": "NTLM hash",
    "ntlm-challenge": "NTLMv1/v2 challenge response",
    "password": "Cleartext password",
    "aes-key": "AES Kerberos key",
    "gmsa": "gMSA managed password",
    "laps": "LAPS password",
    "keycred": "Shadow Credential / KeyCred material",
    "shadow-certificate": "Shadow Cred certificate pair",
}


def _scan_artifacts(session: Session) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []
    seen: set[str] = set()
    for pattern in ARTIFACT_GLOBS:
        for path in sorted(session.root.glob(pattern)):
            if not path.is_file():
                continue
            key = str(path.relative_to(session.root))
            if key in seen:
                continue
            seen.add(key)
            kind = "artifact"
            name = path.name.lower()
            if name.endswith(".ccache"):
                kind = "ccache"
            elif name.endswith(".pfx"):
                kind = "pfx"
            elif name.endswith(".pem"):
                kind = "pem"
            elif "dnbinary" in name:
                kind = "keycred"
            found.append(
                {
                    "source": "session-file",
                    "name": key,
                    "kind": kind,
                    "path": str(path),
                    "size": path.stat().st_size,
                    "label": KIND_LABELS.get(kind, kind),
                }
            )
    return found


def _vault_catalog(session: Session, *, include_secrets: bool) -> list[dict[str, Any]]:
    vault = session.vault()
    items: list[dict[str, Any]] = []
    for entry in vault.list():
        row: dict[str, Any] = {
            "source": "vault",
            "name": entry.name,
            "kind": entry.kind,
            "secret": entry.secret,
            "metadata": entry.metadata,
            "label": KIND_LABELS.get(entry.kind, entry.kind),
        }
        if include_secrets and entry.secret:
            try:
                value = vault.get(entry.name)
                # Never dump full secrets into the primary JSON by default structure;
                # attach a redacted presence flag + type only unless operator insisted.
                row["value_present"] = True
                row["value_type"] = type(value).__name__
                if isinstance(value, dict):
                    row["value_keys"] = sorted(value.keys())
                elif isinstance(value, str):
                    row["value_len"] = len(value)
            except VaultError as exc:
                row["value_error"] = str(exc)
        items.append(row)
    return items


def _inventory(session: Session, *, include_secrets: bool) -> dict[str, Any]:
    vault_items = _vault_catalog(session, include_secrets=include_secrets)
    artifacts = _scan_artifacts(session)
    by_kind: dict[str, int] = {}
    for row in vault_items + artifacts:
        kind = str(row.get("kind") or "unknown")
        by_kind[kind] = by_kind.get(kind, 0) + 1

    return {
        "session": session.session_id,
        "generated_at": datetime.now(UTC).isoformat(),
        "vault_count": len(vault_items),
        "artifact_count": len(artifacts),
        "by_kind": by_kind,
        "vault_items": vault_items,
        "artifacts": artifacts,
        "include_secrets": include_secrets,
        "note": (
            "Inventory is metadata-first. Re-run with --include-secrets and "
            "ADAF_SESSION_VAULT_KEY to confirm decryptability of vault items."
        ),
    }


def _export_items(
    session: Session,
    *,
    names: list[str],
    include_secrets: bool,
) -> dict[str, Any]:
    vault = session.vault()
    export_dir = session.path("credential-export")
    export_dir.mkdir(parents=True, exist_ok=True)
    exported: list[dict[str, str]] = []
    errors: list[dict[str, str]] = []

    for name in names:
        # Vault item
        if vault.exists(name):
            try:
                value = vault.get(name)
                out = export_dir / f"vault-{name}.json"
                if include_secrets:
                    out.write_text(
                        json.dumps(value, indent=2, default=str) + "\n", encoding="utf-8"
                    )
                else:
                    # Metadata-only export
                    meta = next((i.metadata for i in vault.list() if i.name == name), {})
                    out.write_text(
                        json.dumps(
                            {"name": name, "metadata": meta, "note": "secrets redacted"},
                            indent=2,
                        )
                        + "\n",
                        encoding="utf-8",
                    )
                exported.append({"name": name, "path": str(out), "source": "vault"})
            except VaultError as exc:
                errors.append({"name": name, "error": str(exc)})
            continue

        # Session file path (relative)
        try:
            candidate = session.path(name)
        except ValueError:
            errors.append({"name": name, "error": "session path escapes session root"})
            continue
        if candidate.is_file():
            dest = export_dir / candidate.name
            shutil.copy2(candidate, dest)
            exported.append({"name": name, "path": str(dest), "source": "session-file"})
        else:
            errors.append({"name": name, "error": "not found in vault or session files"})

    return {
        "export_dir": str(export_dir),
        "exported": exported,
        "errors": errors,
        "include_secrets": include_secrets,
    }


def _purge(
    session: Session,
    *,
    names: list[str] | None,
    purge_all: bool,
    purge_files: bool,
) -> dict[str, Any]:
    vault = session.vault()
    removed_vault: list[str] = []
    removed_files: list[str] = []

    if purge_all:
        count = vault.purge_all()
        removed_vault = [f"*{count} items*"]
        if purge_files:
            for row in _scan_artifacts(session):
                path = Path(row["path"])
                if path.is_file():
                    path.unlink()
                    removed_files.append(row["name"])
    else:
        for name in names or []:
            if vault.delete(name):
                removed_vault.append(name)
            try:
                candidate = session.path(name)
            except ValueError:
                continue
            if purge_files and candidate.is_file():
                candidate.unlink()
                removed_files.append(name)

    return {
        "removed_vault": removed_vault,
        "removed_files": removed_files,
        "purge_all": purge_all,
    }


def _mark_rotation(session: Session, names: list[str]) -> dict[str, Any]:
    """Record rotation-needed markers without changing directory state."""
    vault = session.vault()
    markers: list[dict[str, Any]] = []
    for name in names:
        meta: dict[str, Any] = {"rotation_needed": True, "marked_at": datetime.now(UTC).isoformat()}
        if vault.exists(name):
            # Preserve existing metadata and value; re-put with rotation flag
            try:
                existing_items = {i.name: i for i in vault.list()}
                item = existing_items[name]
                value = vault.get(name)
                merged = {**item.metadata, **meta}
                vault.put(name, item.kind, value, secret=item.secret, metadata=merged)
                markers.append({"name": name, "ok": True, "source": "vault"})
            except VaultError as exc:
                markers.append({"name": name, "ok": False, "error": str(exc)})
        else:
            markers.append(
                {
                    "name": name,
                    "ok": True,
                    "source": "marker-only",
                    "note": "Not in vault; marker recorded in inventory output only",
                }
            )
    return {"markers": markers}


@register_capability(
    id="credential-inventory",
    summary="Inventory, export, purge, or mark-for-rotation session credential material",
    category="credential-access",
    tags=("vault", "inventory", "export", "purge", "rotation", "credentials"),
    destructive=True,  # purge path is destructive
)
class CredentialInventory:
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
        operation = str(kwargs.get("operation") or "inventory").lower()
        names_raw = kwargs.get("names") or kwargs.get("name") or ""
        if isinstance(names_raw, list):
            names = [str(n).strip() for n in names_raw if str(n).strip()]
        else:
            names = [n.strip() for n in str(names_raw).split(",") if n.strip()]

        console.print(
            f"[bold]Credential inventory[/bold]  op={operation}  session={session.session_id}"
        )

        if operation == "inventory":
            result = _inventory(session, include_secrets=include_secrets)
            table = Table(title="Credential material", show_header=True, header_style="bold")
            table.add_column("Source")
            table.add_column("Name")
            table.add_column("Kind")
            table.add_column("Secret")
            for row in result["vault_items"]:
                table.add_row(
                    "vault",
                    row["name"],
                    row.get("label") or row["kind"],
                    "yes" if row.get("secret") else "no",
                )
            for row in result["artifacts"]:
                table.add_row("file", row["name"], row.get("label") or row["kind"], "file")
            if result["vault_items"] or result["artifacts"]:
                console.print(table)
            else:
                console.print("[dim]No credential material in this session yet.[/dim]")

        elif operation == "export":
            if not names:
                inv = _inventory(session, include_secrets=False)
                names = [r["name"] for r in inv["vault_items"]]
                names += [r["name"] for r in inv["artifacts"]]
            result = {
                "operation": operation,
                **_export_items(session, names=names, include_secrets=include_secrets),
            }
            console.print(
                f"  exported={len(result['exported'])}  errors={len(result['errors'])}  "
                f"dir={result['export_dir']}"
            )

        elif operation == "purge":
            if not force:
                raise RuntimeError("purge requires --force (irreversible vault/file removal)")
            purge_all = bool(kwargs.get("all") or kwargs.get("purge_all"))
            purge_files = bool(kwargs.get("purge_files") if "purge_files" in kwargs else True)
            if not purge_all and not names:
                raise RuntimeError("purge requires -P names=<item1,item2> or -P all=true")
            result = {
                "operation": operation,
                **_purge(
                    session,
                    names=names,
                    purge_all=purge_all,
                    purge_files=purge_files,
                ),
            }
            console.print(
                f"  [red]purged[/red]  vault={result['removed_vault']}  "
                f"files={result['removed_files']}"
            )

        elif operation in {"rotate", "mark-rotation", "mark-for-rotation"}:
            if not names:
                raise RuntimeError("mark-for-rotation requires -P names=<item1,item2>")
            result = {"operation": operation, **_mark_rotation(session, names)}
            console.print(f"  rotation markers={len(result['markers'])}")

        else:
            raise RuntimeError(
                f"Unsupported operation: {operation}. "
                "Use inventory | export | purge | mark-for-rotation"
            )

        if operation == "inventory":
            payload = result
        else:
            # Always attach a fresh inventory snapshot after mutating ops
            payload = {
                **result,
                "inventory_after": _inventory(session, include_secrets=False),
            }

        out = session.path("credential-inventory.json")
        out.write_text(json.dumps(payload, indent=2, default=str) + "\n", encoding="utf-8")
        session.log(
            "credential-inventory.complete",
            operation=operation,
            vault_count=payload.get("vault_count")
            or payload.get("inventory_after", {}).get("vault_count"),
        )
        console.print(f"Results → {out}")
        return payload
