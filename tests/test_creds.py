"""Multi-credential store unit tests."""

import json
from pathlib import Path

from adaf_attack.core.creds import (
    Credential,
    CredentialSet,
    first_working_target,
    load_credentials_json,
)


def test_credential_to_target() -> None:
    c = Credential(username="alice", domain="corp.local", password="x")
    t = c.to_target("10.0.0.1")
    assert t.username == "alice"
    assert t.domain == "corp.local"
    assert t.password == "x"
    assert t.dc_ip == "10.0.0.1"
    assert t.has_credentials


def test_rotation_order() -> None:
    cs = CredentialSet(
        credentials=[
            Credential(username="a", password="1", label="first"),
            Credential(username="b", password="2", label="second"),
            Credential(username="c", hashes=":aabb", label="third"),
        ]
    )
    labels = [c.label for c in cs.rotate(1)]
    assert labels == ["second", "third", "first"]


def test_load_credentials_json_list(tmp_path: Path) -> None:
    p = tmp_path / "creds.json"
    p.write_text(
        json.dumps(
            [
                {"username": "alice", "password": "pw", "domain": "corp.local"},
                {"username": "bob", "hashes": ":deadbeef", "label": "svc"},
            ]
        ),
        encoding="utf-8",
    )
    cs = load_credentials_json(p)
    assert len(cs) == 2
    assert cs.by_label("svc") is not None
    assert cs.by_label("svc").username == "bob"


def test_load_credentials_json_wrapped(tmp_path: Path) -> None:
    p = tmp_path / "creds.json"
    p.write_text(
        json.dumps({"credentials": [{"username": "x", "aes_key": "00" * 16}]}),
        encoding="utf-8",
    )
    cs = load_credentials_json(p)
    assert len(cs) == 1
    assert cs.credentials[0].aes_key is not None


def test_dump_redacted() -> None:
    cs = CredentialSet(credentials=[Credential(username="a", password="secret", hashes="lm:nt")])
    dumped = cs.dump_redacted()
    assert dumped[0]["password"] == "***"
    assert dumped[0]["hashes"] == "***"


def test_first_working_target_with_probe() -> None:
    cs = CredentialSet(
        credentials=[
            Credential(username="bad", password="nope"),
            Credential(username="good", password="yes", label="ok"),
        ]
    )

    def probe(t):  # noqa: ANN001
        return t.username == "good"

    t = first_working_target(cs, "10.0.0.1", "corp.local", probe=probe)
    assert t is not None
    assert t.username == "good"
