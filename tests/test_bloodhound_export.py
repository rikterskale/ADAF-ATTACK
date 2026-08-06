"""BloodHound CE export shape tests."""

import json
from pathlib import Path

from adaf_attack.core.bloodhound import export_bloodhound, save_bloodhound_zip
from adaf_attack.core.graph import AttackGraph


def _sample_graph() -> AttackGraph:
    g = AttackGraph()
    g.add_node(
        "USER@ALICE@CORP.LOCAL",
        "User",
        sam="alice",
        dn="CN=Alice,CN=Users,DC=corp,DC=local",
        sid="S-1-5-21-1-2-3-1001",
        admin_count=False,
    )
    g.add_node(
        "GROUP@DOMAIN ADMINS@CORP.LOCAL",
        "Group",
        sam="Domain Admins",
        dn="CN=Domain Admins,CN=Users,DC=corp,DC=local",
        sid="S-1-5-21-1-2-3-512",
        admin_count=True,
    )
    g.add_node("CA@CORP-CA@CORP.LOCAL", "CA", cn="CORP-CA")
    g.add_node("TEMPLATE@USER@CORP.LOCAL", "CertTemplate", cn="User", esc1_candidate=True)
    g.add_edge("USER@ALICE@CORP.LOCAL", "GROUP@DOMAIN ADMINS@CORP.LOCAL", "MemberOf")
    g.add_edge("USER@ALICE@CORP.LOCAL", "TEMPLATE@USER@CORP.LOCAL", "Enroll")
    g.add_edge("TEMPLATE@USER@CORP.LOCAL", "TEMPLATE@USER@CORP.LOCAL", "ESC1")
    return g


def test_export_has_meta_nodes_edges() -> None:
    doc = export_bloodhound(_sample_graph(), domain="corp.local")
    assert "meta" in doc
    assert "nodes" in doc
    assert "edges" in doc
    assert doc["meta"]["source"] == "adaf-attack"
    assert doc["meta"]["type"] == "bloodhound-ce"
    assert doc["meta"]["version"] == 6
    assert doc["meta"]["domain"] == "CORP.LOCAL"
    assert doc["meta"]["node_count"] == 4
    assert doc["meta"]["edge_count"] == 3


def test_nodes_have_kinds_and_objectid() -> None:
    doc = export_bloodhound(_sample_graph(), domain="corp.local")
    for n in doc["nodes"]:
        assert "kinds" in n and isinstance(n["kinds"], list) and n["kinds"]
        assert "properties" in n
        assert "objectid" in n["properties"]
        assert "domain" in n["properties"]
        assert n["properties"]["domain"] == "CORP.LOCAL"


def test_edge_kinds_mapped() -> None:
    doc = export_bloodhound(_sample_graph(), domain="corp.local")
    labels = {e["label"] for e in doc["edges"]}
    assert "MemberOf" in labels
    assert "Enroll" in labels
    assert "ADCSESC1" in labels  # ESC1 mapped


def test_user_sid_preferred_as_objectid() -> None:
    doc = export_bloodhound(_sample_graph(), domain="corp.local")
    users = [n for n in doc["nodes"] if "User" in n["kinds"]]
    assert users
    assert users[0]["properties"]["objectid"] == "S-1-5-21-1-2-3-1001"
    assert users[0]["id"] == "S-1-5-21-1-2-3-1001"


def test_zip_contains_expected_members(tmp_path: Path) -> None:
    zpath = tmp_path / "bh.zip"
    save_bloodhound_zip(_sample_graph(), zpath, domain="corp.local")
    assert zpath.exists()
    import zipfile

    with zipfile.ZipFile(zpath) as zf:
        names = set(zf.namelist())
        assert "bloodhound.json" in names
        assert "nodes.json" in names
        assert "edges.json" in names
        assert "meta.json" in names
        meta = json.loads(zf.read("meta.json"))
        assert meta["version"] == 6
