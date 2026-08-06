import json
from pathlib import Path

from adaf_attack.core.bloodhound import export_bloodhound, import_bloodhound
from adaf_attack.core.graph import AttackGraph


def test_bloodhound_import_roundtrip(tmp_path: Path) -> None:
    original = AttackGraph()
    original.add_node("USER@ALICE@CORP.LOCAL", "User", sam="alice")
    original.add_node("GROUP@DOMAIN ADMINS@CORP.LOCAL", "Group", admin_count=True)
    original.add_edge("USER@ALICE@CORP.LOCAL", "GROUP@DOMAIN ADMINS@CORP.LOCAL", "MemberOf")
    path = tmp_path / "bloodhound.json"
    path.write_text(json.dumps(export_bloodhound(original)), encoding="utf-8")
    imported = AttackGraph()
    counts = import_bloodhound(path, imported)
    assert counts == {"nodes": 2, "edges": 1}
