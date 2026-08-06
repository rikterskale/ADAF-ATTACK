from pathlib import Path

from adaf_attack.capabilities.sysvol_hunt import SysvolHunt
from adaf_attack.core.graph import AttackGraph
from adaf_attack.core.session import Session
from adaf_attack.core.target import Target


def test_sysvol_hunt_finds_cpassword_without_disclosure(tmp_path: Path) -> None:
    mirror = tmp_path / "sysvol"
    mirror.mkdir()
    (mirror / "Groups.xml").write_text('<User cpassword="AAAA" />', encoding="utf-8")
    session = Session(base_dir=tmp_path)
    result = SysvolHunt().run(
        Target(domain="corp.local", dc_ip="10.0.0.1"), session, AttackGraph(), artifact=str(mirror)
    )
    assert result["count"] == 1
    assert "AAAA" not in (session.root / "sysvol-hunt.json").read_text(encoding="utf-8")
