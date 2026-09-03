"""Behavioral evidence for RM-005 core safety and portability boundaries."""

from __future__ import annotations

import io
import json
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
from ldap3.core.exceptions import LDAPException

import adaf_attack.capabilities  # noqa: F401
from adaf_attack.core import (
    auth,
    capability_profiles,
    cleanup,
    cli_contract,
    command_templates,
    engineering,
    ldap_util,
    paths,
    redaction,
    rollback,
    runner,
    standout_ux,
    ux,
    ux_extra,
)
from adaf_attack.core.graph import AttackGraph
from adaf_attack.core.outcomes import build_post_execution_outcome
from adaf_attack.core.registry import (
    ApprovalPolicy,
    Capability,
    RollbackClass,
    SafetyProfile,
    capability_registry,
)
from adaf_attack.core.session import Session
from adaf_attack.core.target import Target
from adaf_attack.core.vault import SessionVault, VaultError


class _FakeServerInfo:
    def __init__(self, other: dict[str, list[str]]) -> None:
        self.other = other


class _FakeServer:
    def __init__(self, other: dict[str, list[str]]) -> None:
        self.info = _FakeServerInfo(other)


class _FakeConnection:
    result = {"description": "fake result"}

    def __init__(
        self,
        *,
        bound: bool = False,
        open_error: BaseException | None = None,
        start_tls_result: bool = True,
        start_tls_error: BaseException | None = None,
        bind_result: bool = True,
        bind_error: BaseException | None = None,
    ) -> None:
        self.bound = bound
        self.open_error = open_error
        self.start_tls_result = start_tls_result
        self.start_tls_error = start_tls_error
        self.bind_result = bind_result
        self.bind_error = bind_error
        self.opened = False
        self.start_tls_called = False
        self.unbound = False

    def open(self) -> None:
        if self.open_error is not None:
            raise self.open_error
        self.opened = True

    def start_tls(self, *, read_server_info: bool) -> bool:
        assert read_server_info is True
        if self.start_tls_error is not None:
            raise self.start_tls_error
        self.start_tls_called = True
        return self.start_tls_result

    def bind(self) -> bool:
        if self.bind_error is not None:
            raise self.bind_error
        self.bound = self.bind_result
        return self.bind_result

    def unbind(self) -> None:
        self.unbound = True


def _patch_ldap(
    monkeypatch: pytest.MonkeyPatch,
    connection: _FakeConnection,
    other: dict[str, list[str]] | None = None,
) -> None:
    monkeypatch.setattr(ldap_util, "Server", lambda *args, **kwargs: _FakeServer(other or {}))
    monkeypatch.setattr(ldap_util, "Connection", lambda server, **kwargs: connection)


def test_auth_restores_existing_ccache_and_keeps_kerberos_username(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import impacket.krb5.kerberosv5 as kerberosv5

    monkeypatch.setenv("KRB5CCNAME", "original.ccache")
    monkeypatch.setattr(
        kerberosv5,
        "getKerberosTGT",
        lambda *args, **kwargs: ("tgt", "cipher", None, "session"),
    )
    target = Target(
        domain="corp.test",
        dc_ip="10.0.0.1",
        username="alice",
        use_kerberos=True,
        ccache="temporary.ccache",
    )

    assert auth.get_kerberos_tgt(target)[0] == "tgt"
    assert auth.os.environ["KRB5CCNAME"] == "original.ccache"
    assert auth.ldap3_bind_kwargs(target)["user"] == "alice"


def test_ldap_connect_authenticated_starttls_returns_naming_contexts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connection = _FakeConnection()
    _patch_ldap(
        monkeypatch,
        connection,
        {
            "defaultNamingContext": ["DC=corp,DC=test"],
            "configurationNamingContext": ["CN=Configuration,DC=corp,DC=test"],
        },
    )

    bound, default_nc, config_nc = ldap_util.ldap_connect(
        Target(
            domain="corp.test",
            dc_ip="10.0.0.1",
            username="alice",
            password="secret",
            starttls=True,
        )
    )

    assert bound is connection
    assert connection.opened and connection.start_tls_called and connection.bound
    assert default_nc == "DC=corp,DC=test"
    assert config_nc == "CN=Configuration,DC=corp,DC=test"


def test_ldap_connect_anonymous_starttls_falls_back_to_domain_context(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connection = _FakeConnection()
    _patch_ldap(monkeypatch, connection)

    _bound, default_nc, config_nc = ldap_util.ldap_connect(
        Target(domain="corp.test", dc_ip="10.0.0.1", starttls=True)
    )

    assert connection.opened and connection.start_tls_called and connection.bound
    assert default_nc == "DC=corp,DC=test"
    assert config_nc is None


def test_ldap_connect_wraps_open_bind_and_starttls_failures(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    opened = _FakeConnection(open_error=LDAPException("open failed"))
    _patch_ldap(monkeypatch, opened)
    with pytest.raises(RuntimeError, match="LDAP connection error: open failed"):
        ldap_util.ldap_connect(
            Target(domain="corp.test", dc_ip="10.0.0.1", username="alice", use_kerberos=True)
        )

    starttls = _FakeConnection(start_tls_result=False)
    _patch_ldap(monkeypatch, starttls)
    with pytest.raises(RuntimeError, match="LDAP StartTLS failed"):
        ldap_util.ldap_connect(Target(domain="corp.test", dc_ip="10.0.0.1", starttls=True))

    bind_error = _FakeConnection(bind_error=LDAPException("bind failed"))
    _patch_ldap(monkeypatch, bind_error)
    with pytest.raises(RuntimeError, match="LDAP connection error: bind failed"):
        ldap_util.ldap_connect(Target(domain="corp.test", dc_ip="10.0.0.1"))

    bind_false = _FakeConnection(bind_result=False)
    _patch_ldap(monkeypatch, bind_false)
    with pytest.raises(RuntimeError, match="LDAP bind failed"):
        ldap_util.ldap_connect(Target(domain="corp.test", dc_ip="10.0.0.1"))


def test_cleanup_leaves_unknown_future_classification_pending(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    session = tmp_path / "session"
    session.mkdir()
    (session / "cleanup.json").write_text(
        json.dumps([{"status": "pending", "kind": "future-kind", "target": "x"}]),
        encoding="utf-8",
    )
    connection = _FakeConnection(bound=True)
    monkeypatch.setattr(cleanup, "ldap_connect", lambda target: (connection, "", None))
    monkeypatch.setattr(cleanup, "classification_for_kind", lambda kind: "future")

    result = cleanup.execute_cleanup(session, Target(domain="corp.test", dc_ip="10.0.0.1"))

    assert result["completed"] == 0
    assert json.loads((session / "cleanup.json").read_text(encoding="utf-8"))[0]["status"] == (
        "pending"
    )
    assert connection.unbound


def test_paths_best_effort_permissions_and_atomic_cleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class Unchmodable:
        def chmod(self, mode: int) -> None:
            raise OSError("read-only filesystem")

    monkeypatch.setattr(paths, "is_windows", lambda: False)
    item = Unchmodable()
    assert paths.restrict_permissions(item) is item  # type: ignore[arg-type]

    destination = tmp_path / "artifact.json"

    def denied_replace(source: Path, target: Path) -> None:
        raise OSError("replace denied")

    monkeypatch.setattr(paths.os, "replace", denied_replace)
    with pytest.raises(OSError, match="replace denied"):
        paths.atomic_write_bytes(destination, b"payload")
    assert not list(tmp_path.glob(".artifact.json.*"))


def test_cli_error_payload_omits_empty_suggested_command() -> None:
    error = cli_contract.ActionableError("CODE", "message", "remediation")
    payload = error.payload()["error"]
    assert payload["ok"] is False
    assert "suggested_command" not in payload


def test_command_template_edges_preserve_evidence_and_fallback_follow_ons(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = Target(domain="corp.test", dc_ip="10.0.0.1", username="operator")
    explicit = {
        "terminal_relation": "WriteRBCD",
        "start": "COMPUTER@WS01$",
        "end": "COMPUTER@DC01$",
        "spn": "HTTP/dc01.corp.test",
    }
    rendered = command_templates.build_exploit_commands(explicit, target)
    assert "--spn HTTP/dc01.corp.test" in rendered[0]["command"]
    assert command_templates.emit_ranked_paths([explicit], target)[0]["example_commands"]

    monkeypatch.setitem(
        command_templates.SECONDARY_COMMAND_TEMPLATES,
        "NoPrimary",
        [{"label": "follow", "kind": "review", "risk": "low", "cmd": "review {domain}"}],
    )
    fallback = command_templates.build_exploit_commands({"terminal_relation": "NoPrimary"}, target)[
        0
    ]
    assert fallback["follow_on_commands"][0]["command"] == "review corp.test"

    monkeypatch.setitem(
        command_templates.COMMAND_TEMPLATES,
        "BrokenTemplate",
        [{"capability": "broken", "risk": "low", "approval_required": False, "cmd": "run {"}],
    )
    broken = command_templates.build_exploit_commands(
        {"terminal_relation": "BrokenTemplate"}, target
    )[0]
    assert broken["command"] == "run {"


def test_engineering_dependency_filters_handle_cycles_missing_and_malformed_requirements(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Distribution:
        def __init__(self, requires: list[str] | None) -> None:
            self.requires = requires

    installed = {
        "root": Distribution(["Dep>=1", "Ghost>=1", "??? malformed"]),
        "dep": Distribution(["root"]),
    }

    def resolve(name: str) -> Distribution:
        try:
            return installed[name]
        except KeyError as exc:
            raise engineering.PackageNotFoundError(name) from exc

    monkeypatch.setattr(engineering, "distribution", resolve)
    assert engineering.distribution_closure("root") == {"root", "dep", "ghost"}
    failures = engineering.relevant_pip_failures(
        "\nNo broken requirements found.\n??? malformed\nroot 1.0 is broken\nother 2.0 is broken",
        {"root"},
    )
    assert failures == ["??? malformed", "root 1.0 is broken"]


def test_profile_resolution_surfaces_unavailable_runner(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    unavailable = Capability(
        id="rm005-unavailable",
        summary="Unavailable test capability",
        category="lateral-movement",
        runner=None,
    )
    monkeypatch.setattr(capability_profiles, "load_builtin_capabilities", lambda: None)
    monkeypatch.setattr(capability_profiles.capability_registry, "list", lambda: [unavailable])

    resolved = capability_profiles.resolve_profile("lateral-movement")

    assert resolved["capabilities"] == []
    assert resolved["skipped"] == [{"id": "rm005-unavailable", "reason": "runner unavailable"}]


def test_redaction_hit_detection_deduplicates_and_honors_limit() -> None:
    assert redaction.unredacted_secret_hits("password=hunter password=hunter") == [
        "password=hunter"
    ]
    hits = redaction.unredacted_secret_hits(
        "password=one " + "AKIA" + "ABCDEFGHIJKLMNOP " + "ghp_" + "a" * 30,
        limit=1,
    )
    assert len(hits) == 1


def test_rollback_validation_rejects_missing_classification() -> None:
    with pytest.raises(ValueError, match="<missing>"):
        rollback.validate_cleanup_entry({})


def test_runner_restores_bound_rich_console_and_fail_closed_scope_guards(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from rich.console import Console

    stream = io.StringIO()
    fake_module = ModuleType("adaf_attack.capabilities._rm005_console")
    fake_module.console = Console(file=stream)  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, fake_module.__name__, fake_module)
    original = fake_module.console.file  # type: ignore[attr-defined]
    with runner._capture_capability_output():
        fake_module.console.print("muted")  # type: ignore[attr-defined]
    assert fake_module.console.file is original  # type: ignore[attr-defined]

    class NoopRunner:
        def run(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
            return {"ok": True}

    capability = Capability(
        id="rm005-scoped",
        summary="Scoped test capability",
        runner=NoopRunner(),
        safety=SafetyProfile(
            approval=ApprovalPolicy.SCOPED_TOKEN,
            network_side_effect=True,
        ),
    )
    monkeypatch.setitem(capability_registry._capabilities, capability.id, capability)
    monkeypatch.setattr(runner, "enforce_execution_policy", lambda request: None)
    with pytest.raises(runner.RunError, match="requires a scoped approval token"):
        runner.execute_capability(
            capability.id,
            Target(domain="corp.test", dc_ip="10.0.0.1"),
            force=True,
            acknowledged=True,
        )


def test_runner_surfaces_scoped_approval_rejection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from adaf_attack.core import engagement

    class NoopRunner:
        def run(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
            return {"ok": True}

    capability = Capability(
        id="rm005-rejected-scope",
        summary="Rejected scoped test capability",
        runner=NoopRunner(),
        safety=SafetyProfile(
            approval=ApprovalPolicy.SCOPED_TOKEN,
            network_side_effect=True,
        ),
    )
    monkeypatch.setitem(capability_registry._capabilities, capability.id, capability)
    monkeypatch.setattr(runner, "enforce_execution_policy", lambda request: None)

    def reject(*args: Any, **kwargs: Any) -> None:
        raise engagement.EngagementError("scope mismatch")

    monkeypatch.setattr(engagement, "verify_scoped_approval", reject)
    with pytest.raises(runner.RunError, match="Scoped approval rejected: scope mismatch"):
        runner.execute_capability(
            capability.id,
            Target(domain="corp.test", dc_ip="10.0.0.1"),
            force=True,
            acknowledged=True,
            approval_token="token",
            approval_engagement_id="ENG-005",
        )


def test_outcome_preserves_explicit_next_command(tmp_path: Path) -> None:
    session = Session(base_dir=tmp_path)
    outcome = build_post_execution_outcome(
        session.root,
        capability="rm005",
        result={"ok": True, "next_command": "adaf-attack guide"},
        graph=AttackGraph(),
        auth="anonymous",
    )
    assert outcome["next_command"] == "adaf-attack guide"


def test_timeline_skips_blank_and_non_mapping_events(tmp_path: Path) -> None:
    events = tmp_path / "events.jsonl"
    events.write_text(
        "\n[1]\n" + json.dumps({"type": "run.complete", "status": "ok"}) + "\n",
        encoding="utf-8",
    )
    timeline = standout_ux.session_timeline(tmp_path)
    assert timeline["count"] == 1


def test_ux_contracts_cover_fallback_authorization_rollback_and_downstream_evidence() -> None:
    no_safety = Capability(id="rm005-no-safety", summary="No safety")
    object.__setattr__(no_safety, "safety", None)
    assert ux.operator_approvals(no_safety) == ["Review plan output before any live run"]

    network = Capability(
        id="rm005-network",
        summary="Network side effect",
        safety=SafetyProfile(network_side_effect=True),
    )
    assert "Written authorization" in ux.operator_approvals(network)[0]

    automatic = Capability(
        id="rm005-automatic",
        summary="Automatic rollback",
        safety=SafetyProfile(rollback=RollbackClass.AUTOMATIC),
    )
    assert (
        "Mutations record pre-state"
        in ux.operator_rollback_contract(automatic)["rollback_implication"]
    )

    cap = capability_registry.get("ldap-enum")
    assert cap is not None
    contract = ux.operator_capability_contract(cap)
    assert any(item.startswith("evidence for ") for item in contract["evidence_produced"])


def test_ux_extra_stage_advance_preserves_current_for_empty_stage_list() -> None:
    assert ux_extra.advance_stage_from_log([], "anything", current="harvest") == "harvest"


def test_vault_rejects_invalid_and_symlinked_secret_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    vault = SessionVault(tmp_path, key="not-used")
    with pytest.raises(VaultError, match="invalid secret file path"):
        vault._safe_blob_path(None)

    monkeypatch.setattr(Path, "is_symlink", lambda path: path.name == "link")
    with pytest.raises(VaultError, match="may not be symlinks"):
        vault._safe_blob_path("link")
