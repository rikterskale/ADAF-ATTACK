"""Campaign controls: OPSEC policy, cleanup manifests, and evidence packages."""

from __future__ import annotations

import hashlib
import json
import shutil
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from adaf_attack.core.redaction import redact

OPSEC_PROFILES: dict[str, dict[str, Any]] = {
    "stealth": {"ldap_page_size": 100, "max_concurrency": 1, "jitter_ms": [750, 2500], "prefer_ldaps": True},
    "balanced": {"ldap_page_size": 500, "max_concurrency": 2, "jitter_ms": [150, 750], "prefer_ldaps": True},
    "loud": {"ldap_page_size": 1000, "max_concurrency": 8, "jitter_ms": [0, 0], "prefer_ldaps": False},
}


def resolve_opsec(name: str) -> dict[str, Any]:
    if name not in OPSEC_PROFILES:
        raise ValueError(f"Unknown OPSEC profile: {name}")
    return {"name": name, **OPSEC_PROFILES[name]}


def _manifest(root: Path, profile: str) -> dict[str, Any]:
    files = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or "vault" in path.parts:
            continue
        files.append({"path": str(path.relative_to(root)), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
    return {"generated_at": datetime.now(UTC).isoformat(), "redaction_profile": profile, "files": files}


def package_evidence(session: Path, destination: Path, *, profile: str = "client") -> dict[str, Any]:
    """Create a redacted engagement archive without copying vault ciphertext."""
    if not session.is_dir():
        raise ValueError("Session directory does not exist")
    staging = destination.with_suffix("")
    if staging.exists():
        shutil.rmtree(staging)
    staging.mkdir(parents=True)
    for path in session.rglob("*"):
        if not path.is_file() or "vault" in path.parts:
            continue
        target = staging / path.relative_to(session)
        target.parent.mkdir(parents=True, exist_ok=True)
        if path.suffix == ".json":
            try:
                target.write_text(json.dumps(redact(json.loads(path.read_text(encoding="utf-8")), profile=profile), indent=2) + "\n", encoding="utf-8")
                continue
            except (OSError, json.JSONDecodeError):
                pass
        shutil.copy2(path, target)
    manifest = _manifest(staging, profile)
    (staging / "evidence-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    archive = shutil.make_archive(str(staging), "zip", root_dir=staging)
    return {"archive": archive, "manifest": str(staging / "evidence-manifest.json"), "file_count": len(manifest["files"]), "profile": profile}
