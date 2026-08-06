import json

import yaml

from adaf_attack.core import forest_campaign


def test_run_campaign_stops_after_failed_engagement(tmp_path, monkeypatch) -> None:
    first = tmp_path / "first.yaml"
    second = tmp_path / "second.yaml"
    first.write_text("engagement_id: one\n", encoding="utf-8")
    second.write_text("engagement_id: two\n", encoding="utf-8")
    manifest = tmp_path / "campaign.yaml"
    manifest.write_text(
        yaml.safe_dump(
            {"campaign_id": "campaign-1", "engagements": [{"plan": first.name}, {"plan": second.name}]}
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
        {"engagement_id": "one", "domain": "corp.example", "session_path": str(tmp_path / "session-one")}
    ]


def test_campaign_manifest_rejects_missing_plan(tmp_path) -> None:
    manifest = tmp_path / "campaign.yaml"
    manifest.write_text(json.dumps({"campaign_id": "c", "engagements": [{"plan": "missing.yaml"}]}), encoding="utf-8")
    try:
        forest_campaign.load_campaign_manifest(manifest)
    except forest_campaign.CampaignError as exc:
        assert "not found" in str(exc)
    else:
        raise AssertionError("Expected CampaignError")
