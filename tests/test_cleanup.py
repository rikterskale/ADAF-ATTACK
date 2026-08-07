import json

from adaf_attack.core import cleanup
from adaf_attack.core.target import Target


def test_cleanup_deletes_only_recorded_staged_sysvol_file(tmp_path, monkeypatch) -> None:
    session = tmp_path / "session"
    session.mkdir()
    (session / "cleanup.json").write_text(
        json.dumps(
            [
                {
                    "status": "pending",
                    "kind": "gpo-sysvol",
                    "target": "corp.example/Policies/{GUID}/Machine/adaf_staged.xml",
                    "host": "10.0.0.10",
                }
            ]
        ),
        encoding="utf-8",
    )

    class Connection:
        result = {}

        def unbind(self) -> None:
            pass

    deleted: list[tuple[str, str]] = []

    class Smb:
        def deleteFile(self, share: str, path: str) -> None:
            deleted.append((share, path))

        def logoff(self) -> None:
            pass

    monkeypatch.setattr(cleanup, "ldap_connect", lambda _target: (Connection(), "", {}))
    monkeypatch.setattr(
        "adaf_attack.capabilities.gpo_sysvol._smb_connect", lambda _target, _host: Smb()
    )

    result = cleanup.execute_cleanup(session, Target(domain="corp.example", dc_ip="10.0.0.10"))

    assert deleted == [("SYSVOL", "corp.example\\Policies\\{GUID}\\Machine\\adaf_staged.xml")]
    assert result["completed"] == 1
