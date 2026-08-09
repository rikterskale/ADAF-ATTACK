import json

import yaml
from adaf_attack.core import forest_campaign
from adaf_attack.core.session import Session
from cryptography.fernet import Fernet


def test_run_campaign_stops_after_failed_engagement(tmp_path, monkeypatch) -> None:
    first = tmp_path / "first.yaml"
    second = tmp_path / "second.yaml"
    first.write_text("engagement_id: one\n", encoding="utf-8")
    second.write_text("engagement_id: two\n", encoding="utf-8")
    manifest = tmp_path / "campaign.yaml"
    manifest.write_text(
        yaml.safe_dump(
            {
                "campaign_id": "campaign-1",
                "engagements": [{"plan": first.name}, {"plan": second.name}],
            }
        ),
        encoding="utf-8",
    )

    class Plan:
        def __init__(self, engagement_id: str) -> None:
            self.engagement_id = engagement_id
            self.domain = "corp.example"

    monkeypatch.setattr(
        "adaf_attack.core.engagement.load_plan",
        lambda path: Plan("one" if path == first else "two"),
    )
    calls: list[str] = []

    def fake_run(plan, **_kwargs):
        calls.append(plan.engagement_id)
        if plan.engagement_id == "two":
            raise RuntimeError("scope denied")
        return {"session_path": str(tmp_path / "session-one")}

    monkeypatch.setattr("adaf_attack.core.engagement.run_engagement", fake_run)
    result = forest_campaign.run_campaign(manifest, workspace=tmp_path / "workspaces")

    assert calls == ["one", "two"]
    assert result["stopped"] is True
    assert result["failed_engagement"] == "two"
    assert result["completed"] == [
        {
            "engagement_id": "one",
            "domain": "corp.example",
            "session_path": str(tmp_path / "session-one"),
            "credential_handoff": None,
        }
    ]


def test_campaign_manifest_rejects_missing_plan(tmp_path) -> None:
    manifest = tmp_path / "campaign.yaml"
    manifest.write_text(
        json.dumps({"campaign_id": "c", "engagements": [{"plan": "missing.yaml"}]}),
        encoding="utf-8",
    )
    try:
        forest_campaign.load_campaign_manifest(manifest)
    except forest_campaign.CampaignError as exc:
        assert "not found" in str(exc)
    else:
        raise AssertionError("Expected CampaignError")


def test_campaign_handoff_requires_explicit_opt_in(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("ADAF_SESSION_VAULT_KEY", Fernet.generate_key().decode())
    source = Session(base_dir=tmp_path / "source")
    ccache = source.path("ticket.ccache")
    ccache.write_bytes(b"ccache")
    source.vault().put("tgt", "ccache", {"path": str(ccache)}, secret=True)
    plan_path = tmp_path / "one.yaml"
    plan_path.write_text("engagement_id: one\n", encoding="utf-8")
    manifest = tmp_path / "campaign.yaml"
    manifest.write_text(
        yaml.safe_dump(
            {
                "campaign_id": "campaign-1",
                "engagements": [
                    {
                        "plan": plan_path.name,
                        "credential_handoff": {
                            "allow": True,
                            "from_session": str(source.root),
                            "item": "tgt",
                        },
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    class Plan:
        engagement_id = "one"
        domain = "corp.example"

    monkeypatch.setattr("adaf_attack.core.engagement.load_plan", lambda _path: Plan())
    captured: dict[str, object] = {}

    def fake_run(_plan, **kwargs):
        captured.update(kwargs)
        session = tmp_path / "output-session"
        session.mkdir()
        (session / "session.json").write_text(
            json.dumps({"domain": "corp.example"}), encoding="utf-8"
        )
        return {"session_path": str(session)}

    monkeypatch.setattr("adaf_attack.core.engagement.run_engagement", fake_run)
    result = forest_campaign.run_campaign(manifest, workspace=tmp_path / "workspaces")

    assert captured["ccache"] == str(ccache)
    assert result["completed"][0]["credential_handoff"]["item"] == "tgt"
