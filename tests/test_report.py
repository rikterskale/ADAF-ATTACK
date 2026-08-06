"""Operator report generation (offline)."""

import json
from pathlib import Path

from adaf_attack.capabilities.report import Report
from adaf_attack.core.graph import AttackGraph
from adaf_attack.core.session import Session
from adaf_attack.core.target import Target


def test_report_builds_md_html(tmp_path: Path) -> None:
    # Session rooted at tmp
    sess = Session(base_dir=tmp_path)
    # Seed minimal artifacts
    g = AttackGraph()
    g.add_node("USER@ALICE@CORP.LOCAL", "User", sam="alice")
    g.add_node("GROUP@DOMAIN ADMINS@CORP.LOCAL", "Group", sam="Domain Admins", admin_count=True)
    g.add_edge("USER@ALICE@CORP.LOCAL", "GROUP@DOMAIN ADMINS@CORP.LOCAL", "MemberOf")
    g.save(sess.path("graph.json"))
    sess.path("interesting.json").write_text(
        json.dumps(
            {
                "top_paths": [
                    {
                        "path": ["USER@ALICE@CORP.LOCAL", "GROUP@DOMAIN ADMINS@CORP.LOCAL"],
                        "score": 1.5,
                        "length": 1,
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    sess.path("adcs-enum.json").write_text(
        json.dumps(
            {
                "cas": [],
                "templates": [],
                "esc1_candidates": ["User"],
                "esc2_candidates": [],
                "esc4_acl_templates": [],
                "esc7_ca_acl": [],
                "esc8_web_enrollment": [],
                "esc6": {"resolved": False},
            }
        ),
        encoding="utf-8",
    )

    target = Target(domain="corp.local", dc_ip="10.0.0.1")
    out = Report().run(target, sess, g)
    assert Path(out["md_path"]).is_file()
    assert Path(out["html_path"]).is_file()
    md = Path(out["md_path"]).read_text(encoding="utf-8")
    assert "Operator Report" in md
    assert "corp.local" in md
    assert "ESC1" in md or "User" in md
