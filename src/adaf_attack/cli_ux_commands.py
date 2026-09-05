"""CLI UX command registration (profiles, demo, completions, session show)."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

import typer
from rich.panel import Panel
from rich.table import Table

from adaf_attack.core.cli_contract import ActionableError, error_for
from adaf_attack.core.paths import default_workspace_dir


def register_ux_commands(
    app: typer.Typer,
    session_app: typer.Typer,
    *,
    emit: Callable[..., None],
    emit_error: Callable[..., None],
    json_mode: Callable[..., bool],
    console: Callable[..., Any],
    doctor_payload: Callable[..., dict[str, Any]],
) -> None:
    """Attach profile/demo/completions/session-show commands to the main CLI app."""
    _emit = emit
    _emit_error = emit_error
    _json_mode = json_mode
    _console = console

    @app.command("quickstart", rich_help_panel="Setup & diagnostics")
    def quickstart_cmd(
        ctx: typer.Context,
        workspace: Path | None = typer.Option(
            None, "--workspace", help="Where to create the disposable offline demo session."
        ),
    ) -> None:
        """Run the complete safe first-install check and offline demo."""
        from adaf_attack.core.ux import session_findings_dashboard
        from adaf_attack.demo import materialize_demo_session

        doctor = doctor_payload("user-readiness")
        if not doctor["ok"]:
            from adaf_attack.core.journey import guide_recovery_command

            blocking: dict[str, Any] = next(
                (item for item in doctor.get("checks", []) if item.get("status") == "error"),
                {},
            )
            error = error_for(
                "QUICKSTART_READINESS_BLOCKED",
                message=str(
                    blocking.get("value")
                    or blocking.get("detail")
                    or "User-readiness doctor reported a blocking check."
                ),
                details={
                    "workspace": str(workspace) if workspace is not None else None,
                    "doctor": doctor,
                    "blocking_check": blocking.get("id"),
                },
                suggested_command=str(
                    blocking.get("repair_command")
                    or "adaf-attack doctor --profile user-readiness --explain"
                ),
            )
            payload = {
                "ok": False,
                "stage": "doctor",
                "doctor": doctor,
                "error": error.payload()["error"],
                "next_step": error.suggested_command,
                "suggested_command": error.suggested_command,
                "recovery_command": guide_recovery_command(workspace=workspace),
            }
            _emit(
                ctx,
                payload,
                Panel(
                    f"Quickstart stopped at doctor.\nNext: {payload['next_step']}",
                    title="ADAF-ATTACK quickstart",
                ),
            )
            raise typer.Exit(code=1)

        dest_root = workspace or (default_workspace_dir() / "quickstart")
        dest = dest_root / "demo-session"
        if dest.exists():
            error = ActionableError(
                "QUICKSTART_WORKSPACE_EXISTS",
                f"The quickstart session already exists: {dest}",
                "Choose an empty directory with `--workspace <path>` or remove the disposable quickstart session yourself.",
                suggested_command="adaf-attack quickstart --workspace ./quickstart-2",
            )
            _emit_error(ctx, error)
            raise typer.Exit(code=error.exit_code)
        try:
            materialize_demo_session(dest)
        except (OSError, FileNotFoundError) as exc:
            error = ActionableError(
                "QUICKSTART_WRITE_FAILED",
                f"Could not create the quickstart demo session: {exc}",
                "Choose a writable directory with `adaf-attack paths` and rerun `adaf-attack quickstart --workspace <path>`.",
                suggested_command="adaf-attack paths",
            )
            _emit_error(ctx, error)
            raise typer.Exit(code=error.exit_code) from exc

        from adaf_attack.core.journey import guide_recovery_command, quote_path

        dashboard = session_findings_dashboard(dest)
        guide_workspace = dest_root
        next_guide = guide_recovery_command(workspace=guide_workspace, session=dest)
        payload = {
            "ok": True,
            "stage": "complete",
            "checks": [
                "doctor --profile user-readiness",
                "packaged demo fixtures",
                "offline demo session",
            ],
            "doctor": doctor,
            "session_path": str(dest),
            "dashboard": dashboard,
            "next_step": next_guide,
            "suggested_command": next_guide,
            "recovery_command": next_guide,
            "next_steps": [
                next_guide,
                f"adaf-attack session show --session {quote_path(dest)}",
                (
                    "adaf-attack engagement report "
                    f"--session {quote_path(dest)} --engagement-id QUICKSTART-2026-001"
                ),
                "Read docs/USER_READINESS.md before connecting to an authorized target.",
            ],
        }
        _emit(
            ctx,
            payload,
            Panel(
                "Installation and offline demo passed.\n"
                f"Session: {dest}\n"
                f"Findings: {dashboard.get('finding_count', 0)}\n"
                f"Next: {next_guide}",
                title="ADAF-ATTACK quickstart",
            ),
        )

    @app.command("start-here", rich_help_panel="Setup & diagnostics")
    def start_here_cmd(
        ctx: typer.Context,
        workspace: Path | None = typer.Option(
            None, "--workspace", help="Where to create the disposable offline demo session."
        ),
    ) -> None:
        """Beginner-friendly alias for the safe first-install flow."""
        quickstart_cmd(ctx, workspace)

    @app.command("guide", rich_help_panel="Guidance & UX helpers")
    def guide_cmd(
        ctx: typer.Context,
        workspace: Path | None = typer.Option(
            None, "--workspace", help="Workflow workspace (defaults to the shared workspace)."
        ),
        session: Path | None = typer.Option(
            None, "--session", help="Bias operate/deliver stages toward this session."
        ),
        advance: bool = typer.Option(
            False,
            "--advance",
            help="TTY-only: complete the safe primary offline step when allowed.",
        ),
    ) -> None:
        """Show where you are and the one copy-ready next step for the guided journey."""
        from adaf_attack.core.journey import import_session_findings, snapshot
        from adaf_attack.core.workflow_engine import WorkflowEngine, WorkflowError
        from adaf_attack.demo import materialize_demo_session

        doctor = doctor_payload("user-readiness")
        root = Path(workspace) if workspace is not None else default_workspace_dir()
        payload = snapshot(workspace=root, session=session, doctor=doctor)

        if advance:
            non_interactive = bool(ctx.ensure_object(dict).get("non_interactive"))
            primary = payload["primary_action"]
            if payload.get("error"):
                error_payload = payload["error"]
                error = ActionableError(
                    str(error_payload["code"]),
                    str(error_payload["message"]),
                    str(error_payload["remediation"]),
                    suggested_command=str(error_payload.get("suggested_command") or ""),
                )
                _emit_error(ctx, error)
                raise typer.Exit(code=error.exit_code)
            if non_interactive or _json_mode(ctx):
                error = error_for(
                    "INTERACTIVE_MODE_DISABLED",
                    message="`guide --advance` requires an interactive TTY.",
                    suggested_command="adaf-attack guide",
                )
                # Keep the advance-specific remediation while retaining the catalog code.
                error = ActionableError(
                    error.code,
                    error.message,
                    "Run `adaf-attack guide` and copy the suggested command, or omit `--format json`.",
                    suggested_command=error.suggested_command,
                )
                _emit_error(ctx, error)
                raise typer.Exit(code=error.exit_code)
            if not primary.get("advance_safe"):
                error = error_for(
                    "GUIDE_ADVANCE_UNSAFE",
                    message=f"The primary step `{primary['id']}` cannot be auto-advanced.",
                    suggested_command=str(primary.get("suggested_command") or "adaf-attack guide"),
                )
                _emit_error(ctx, error)
                raise typer.Exit(code=error.exit_code)
            action_id = str(primary["id"])
            try:
                if action_id == "quickstart":
                    dest_root = root
                    dest = root / "demo-session"
                    if not dest.exists():
                        materialize_demo_session(dest)
                    payload = snapshot(workspace=dest_root, session=dest, doctor=doctor)
                    payload["advanced"] = {"id": action_id, "session_path": str(dest)}
                elif action_id == "import-session":
                    target = session or Path(str(payload["context"].get("session_hint") or ""))
                    if not target or not target.is_dir():
                        raise FileNotFoundError("No session available to import")
                    imported = import_session_findings(root, target, actor="guide")
                    payload = snapshot(workspace=root, session=target, doctor=doctor)
                    payload["advanced"] = imported
                elif action_id == "workflow-close":
                    engine = WorkflowEngine(root, mode="interactive")
                    engine.close(actor="guide")
                    payload = snapshot(workspace=root, session=session, doctor=doctor)
                    payload["advanced"] = {"id": action_id}
                else:
                    error = error_for(
                        "GUIDE_ADVANCE_UNSAFE",
                        message=f"No safe advance handler for `{action_id}`.",
                        suggested_command=str(
                            primary.get("suggested_command") or "adaf-attack guide"
                        ),
                    )
                    _emit_error(ctx, error)
                    raise typer.Exit(code=error.exit_code)
            except (OSError, FileNotFoundError, WorkflowError) as exc:
                error = error_for(
                    "WORKFLOW_TRANSITION_INVALID",
                    message=str(exc),
                    details={"action": action_id, "workspace": str(root)},
                )
                _emit_error(ctx, error)
                raise typer.Exit(code=error.exit_code) from exc

        primary = payload["primary_action"]
        breadcrumb = " → ".join(
            ("✓ " if item["done"] else ("● " if item["current"] else "○ ")) + item["label"]
            for item in payload.get("breadcrumb") or []
        )
        from adaf_attack.core.journey import journey_summary_lines

        human = Panel(
            "\n".join(
                [
                    breadcrumb,
                    "",
                    *journey_summary_lines(payload, include_secondary=True),
                    "",
                    "Tip: `adaf-attack guide --advance` runs safe offline steps only.",
                ]
            ),
            title="ADAF-ATTACK guide",
        )
        _emit(ctx, payload, human)
        if not payload.get("ok"):
            raise typer.Exit(code=1)

    @app.command("explain", rich_help_panel="Guidance & UX helpers")
    def explain_cmd(
        ctx: typer.Context,
        capability: str = typer.Argument(..., help="Capability ID to explain in plain language."),
    ) -> None:
        """Explain what a capability does, its safety level, and what to do first."""
        from adaf_attack.core.capability_help_data import capability_option_spec
        from adaf_attack.core.novice import capability_difficulty, plain_description, safety_summary
        from adaf_attack.core.registry import capability_registry
        from adaf_attack.core.ux import build_ready_command, capability_prerequisites

        cap = capability_registry.get(capability)
        if cap is None:
            error = ActionableError(
                "UNKNOWN_CAPABILITY",
                f"Unknown capability: {capability}",
                "Run `adaf-attack list-capabilities --novice` to browse beginner-friendly capabilities.",
                suggested_command="adaf-attack list-capabilities --novice --safe-only",
            )
            _emit_error(ctx, error)
            raise typer.Exit(code=error.exit_code)
        from adaf_attack.core.ux import operator_capability_contract

        safety = safety_summary(cap)
        difficulty = capability_difficulty(cap)
        spec = capability_option_spec(cap.id, cap.requires_force)
        prerequisites = capability_prerequisites(cap.id)
        contract = operator_capability_contract(cap)
        payload = {
            "ok": True,
            "capability": {
                "id": cap.id,
                "summary": cap.summary,
                "plain_description": plain_description(cap),
                "category": cap.category,
                "safety": safety,
                "difficulty": difficulty,
                "required_options": list(spec.required),
                "optional_options": list(spec.optional),
                "required_params": list(contract["required_params"]),
                "prerequisites": prerequisites,
                "risk": contract["risk"],
                "approvals": list(contract["approvals"]),
                "rollback": contract["rollback"],
                "rollback_implication": contract["rollback_implication"],
                "rollback_command": contract["rollback_command"],
                "not_rolled_back": contract["not_rolled_back"],
                "after_run_command": contract["after_run_command"],
                "evidence_produced": list(contract["evidence_produced"]),
                "stages": list(contract["stages"]),
                "next_command": contract["copy_ready_command"] or build_ready_command(cap.id),
                "operator_contract": contract,
            },
        }
        human = Panel(
            f"{plain_description(cap)}\n\n"
            f"Safety: {safety['level']} — {safety['plain']}\n"
            f"Risk: {contract['risk']}\n"
            f"Approvals: {', '.join(contract['approvals']) or 'none (observe / review-only)'}\n"
            f"Rollback: {contract['rollback_implication']}\n"
            f"Rollback command: {contract['rollback_command']}\n"
            f"Not rolled back: {contract['not_rolled_back']}\n"
            f"Difficulty: {difficulty['level']} — {difficulty['reason']}\n"
            f"Required information: {', '.join(spec.required) or 'none'}\n"
            f"Required -P: {', '.join(contract['required_params']) or 'none'}\n"
            f"Evidence produced: {', '.join(contract['evidence_produced'])}\n"
            f"Best run after: {', '.join(prerequisites['best_run_after']) or 'none'}\n\n"
            f"After run: {contract['after_run_command']}\n"
            "Next: review the plan with `adaf-attack plan <id> -d <domain> --dc-ip <dc>`.",
            title=f"Plain-language explanation: {cap.id}",
        )
        _emit(ctx, payload, human)

    @app.command("what-next", rich_help_panel="Guidance & UX helpers")
    def what_next_cmd(
        ctx: typer.Context,
        capability: str | None = typer.Argument(None, help="Capability just completed, if known."),
        safe_only: bool = typer.Option(
            True, "--safe-only/--include-advanced", help="Prefer beginner-safe suggestions."
        ),
        workspace: Path | None = typer.Option(
            None,
            "--workspace",
            help="Workflow workspace (must match guide --workspace for identical next steps).",
        ),
        session: Path | None = typer.Option(
            None,
            "--session",
            help="Bias the shared journey snapshot toward this session (same as guide --session).",
        ),
        mode: str = typer.Option(
            "OBSERVE", "--mode", help="Operational mode when attaching session evidence context."
        ),
        rank_by: str = typer.Option(
            "balanced", "--rank-by", help="Ranking mode for optional session evidence context."
        ),
    ) -> None:
        """Recommend the next action; always shares guide's suggested_command."""
        from adaf_attack.core.journey import (
            journey_evidence_summary,
            journey_summary_lines,
            snapshot,
        )
        from adaf_attack.core.novice import beginner_next_actions, home_actions

        if capability is None:
            doctor = doctor_payload("user-readiness")
            root = Path(workspace) if workspace is not None else default_workspace_dir()
            journey = snapshot(workspace=root, session=session, doctor=doctor)
            primary = journey["primary_action"]
            actions = [
                {
                    "goal": primary["title"],
                    "command": primary["suggested_command"],
                    "why": primary["why"],
                    "risk": primary.get("risk"),
                    "evidence_basis": primary.get("evidence_basis") or [],
                }
            ]
            for item in journey.get("secondary_actions") or []:
                actions.append(
                    {
                        "goal": item["title"],
                        "command": item["suggested_command"],
                        "why": item["why"],
                        "risk": item.get("risk"),
                        "evidence_basis": item.get("evidence_basis") or [],
                    }
                )
            # Keep classic goal list as additional suggestions for discoverability.
            for item in home_actions(first_run=bool(journey["context"].get("first_run"))):
                if item["command"] not in {entry["command"] for entry in actions}:
                    actions.append(
                        {
                            **item,
                            "evidence_basis": [
                                {
                                    "kind": "catalog",
                                    "ref": "home-actions",
                                    "summary": "Static discoverability option; journey action remains primary.",
                                }
                            ],
                        }
                    )
            session_context: dict[str, Any] | None = None
            if session is not None and session.is_dir():
                from adaf_attack.core.engagement_dashboard import dashboard

                view = dashboard(session, mode=mode, ranking=rank_by)
                session_context = {
                    "session": str(session),
                    "mode": view["engagement"]["mode"],
                    "ranking": view["ranking"],
                    "objective": view["objective"],
                    "breadcrumbs": view["breadcrumbs"],
                    "evidence_suggestions": view["recommended_next_actions"],
                }
                for item in view["recommended_next_actions"]:
                    command = str(item.get("command") or item.get("action") or "")
                    if command and command not in {entry["command"] for entry in actions}:
                        actions.append(
                            {
                                "goal": str(item.get("action") or "Session evidence action"),
                                "command": command,
                                "why": str(item.get("why") or ""),
                                "risk": item.get("risk"),
                                "evidence_basis": [
                                    {
                                        "kind": "session",
                                        "ref": str(session),
                                        "summary": "Derived from the saved engagement dashboard.",
                                    }
                                ],
                            }
                        )
            payload = {
                "ok": bool(journey.get("ok")),
                "context": "journey",
                "stage": journey["stage"],
                "suggestions": actions,
                "primary_action": primary,
                "next_step": primary["suggested_command"],
                "suggested_command": primary["suggested_command"],
                "recovery_command": journey.get("recovery_command"),
                "journey": journey,
                "session_context": session_context,
            }
            if journey.get("error"):
                payload["error"] = journey["error"]
            human = Panel(
                "\n".join(
                    [
                        *journey_summary_lines(journey, compact=True),
                        "",
                        *[
                            f"{i + 1}. {item['goal']}\n"
                            f"   {item['command']}\n"
                            f"   {item['why']}\n"
                            f"   Evidence: {journey_evidence_summary(item)}"
                            for i, item in enumerate(actions[:6])
                        ],
                    ]
                ),
                title="What should I do next?",
            )
            _emit(ctx, payload, human)
            if not payload["ok"]:
                raise typer.Exit(code=1)
            return
        from adaf_attack.core.registry import capability_registry

        cap = capability_registry.get(capability)
        if cap is None:
            error = ActionableError(
                "UNKNOWN_CAPABILITY",
                f"Unknown capability: {capability}",
                "Run `adaf-attack list-capabilities --novice` to find a valid capability.",
                suggested_command="adaf-attack list-capabilities --novice",
            )
            _emit_error(ctx, error)
            raise typer.Exit(code=error.exit_code)
        suggestions = beginner_next_actions(cap)
        if safe_only:
            from adaf_attack.core.novice import safety_summary

            suggestions = [
                item
                for item in suggestions
                if (follow := capability_registry.get(item["id"])) is not None
                and safety_summary(follow)["level"] != "RED"
            ]
        evidence_suggestions: list[dict[str, Any]] = [
            {
                **item,
                "evidence_basis": [
                    {
                        "kind": "capability-catalog",
                        "ref": str(item["id"]),
                        "summary": f"Static follow-up for completed capability {capability}.",
                    }
                ],
            }
            for item in suggestions
        ]
        doctor = doctor_payload("user-readiness")
        root = Path(workspace) if workspace is not None else default_workspace_dir()
        journey = snapshot(workspace=root, session=session, doctor=doctor)
        primary = journey["primary_action"]
        payload = {
            "ok": bool(journey.get("ok")),
            "context": "journey",
            "completed_capability": capability,
            "stage": journey["stage"],
            "suggestions": evidence_suggestions,
            "primary_action": primary,
            "next_step": primary["suggested_command"],
            "suggested_command": primary["suggested_command"],
            "recovery_command": journey.get("recovery_command"),
            "journey": journey,
        }
        if journey.get("error"):
            payload["error"] = journey["error"]
        human = Panel(
            "\n".join(
                [
                    *journey_summary_lines(journey, compact=True),
                    "",
                    "Capability-specific follow-ups:",
                    *[
                        f"{i + 1}. {item['id']} — {item['message']}\n"
                        f"   Evidence: {journey_evidence_summary(item)}"
                        for i, item in enumerate(evidence_suggestions)
                    ],
                ]
            ),
            title=f"What next after {capability}?",
        )
        _emit(ctx, payload, human)
        if not payload["ok"]:
            raise typer.Exit(code=1)

    # --- Profile management (named target + opsec profiles) --------------------
    profile_app = typer.Typer(help="Named target and opsec profiles.")
    app.add_typer(profile_app, name="profile", rich_help_panel="Guidance & UX helpers")

    @profile_app.command("list")
    def profile_list(ctx: typer.Context) -> None:
        """List saved target profiles."""
        from adaf_attack.core.profiles import list_profiles
        from adaf_attack.core.user_config import get_key

        profiles = list_profiles()
        default_name = get_key("profile.default")
        payload = {
            "ok": True,
            "default": default_name,
            "profiles": [{**p, "is_default": p.get("name") == default_name} for p in profiles],
            "count": len(profiles),
        }
        if not profiles:
            human: Any = Panel(
                "No profiles saved.\nCreate one with: adaf-attack profile set engagement --domain corp.example --dc-ip 10.0.0.10",
                title="Profiles",
            )
        else:
            table = Table(title="Target profiles", show_header=True)
            table.add_column("Name")
            table.add_column("Domain")
            table.add_column("DC")
            table.add_column("User")
            table.add_column("Opsec")
            table.add_column("Default")
            for p in profiles:
                table.add_row(
                    str(p.get("name") or "-"),
                    str(p.get("domain") or "-"),
                    str(p.get("dc_ip") or "-"),
                    str(p.get("username") or "-"),
                    str(p.get("opsec_profile") or "balanced"),
                    "yes" if p.get("name") == default_name else "-",
                )
            human = table
        _emit(ctx, payload, human)

    @profile_app.command("show")
    def profile_show(ctx: typer.Context, name: str = typer.Argument(...)) -> None:
        """Show one profile."""
        from adaf_attack.core.profiles import get_profile

        profile = get_profile(name)
        if profile is None:
            error = ActionableError(
                "UNKNOWN_PROFILE",
                f"Unknown profile: {name}",
                "Run `adaf-attack profile list` to see saved profiles.",
                suggested_command="adaf-attack profile list",
            )
            _emit_error(ctx, error)
            raise typer.Exit(code=error.exit_code)
        payload = {"ok": True, "profile": {"name": name, **profile}}
        human = Panel(
            "\n".join(
                [
                    f"Name: {name}",
                    f"Domain: {profile.get('domain') or '-'}",
                    f"DC: {profile.get('dc_ip') or '-'}",
                    f"Username: {profile.get('username') or '-'}",
                    f"Opsec: {profile.get('opsec_profile') or 'balanced'}",
                    f"LDAPS: {profile.get('ldaps', False)}",
                    f"Kerberos: {profile.get('kerberos', False)}",
                    f"Notes: {profile.get('notes') or '-'}",
                ]
            ),
            title=f"Profile: {name}",
        )
        _emit(ctx, payload, human)

    @profile_app.command("set")
    def profile_set(
        ctx: typer.Context,
        name: str = typer.Argument(..., help="Profile name."),
        domain: str = typer.Option("", "--domain", "-d"),
        dc_ip: str = typer.Option("", "--dc-ip"),
        username: str = typer.Option("", "--username", "-u"),
        opsec: str = typer.Option("balanced", "--opsec", help="stealth | balanced | loud"),
        ldaps: bool = typer.Option(False, "--ldaps"),
        kerberos: bool = typer.Option(False, "--kerberos"),
        notes: str = typer.Option("", "--notes"),
        make_default: bool = typer.Option(False, "--default", help="Also mark as default profile."),
    ) -> None:
        """Create or update a named target profile."""
        from adaf_attack.core.profiles import VALID_OPSEC, apply_profile_to_defaults, set_profile
        from adaf_attack.core.user_config import set_key

        if opsec not in VALID_OPSEC:
            error = ActionableError(
                "INVALID_OPSEC_PROFILE",
                f"Invalid opsec profile: {opsec}",
                f"Choose one of: {', '.join(VALID_OPSEC)}",
                suggested_command="adaf-attack profile set engagement --opsec balanced",
            )
            _emit_error(ctx, error)
            raise typer.Exit(code=error.exit_code)
        values = {
            "domain": domain,
            "dc_ip": dc_ip,
            "username": username,
            "opsec_profile": opsec,
            "ldaps": ldaps,
            "kerberos": kerberos,
            "notes": notes,
        }
        values = {k: v for k, v in values.items() if v != "" and v is not None}
        try:
            saved = set_profile(name, values)
        except ValueError as exc:
            error = ActionableError(
                "INVALID_PROFILE",
                str(exc),
                "Correct the profile fields and try again.",
                suggested_command="adaf-attack profile list",
            )
            _emit_error(ctx, error)
            raise typer.Exit(code=error.exit_code) from exc
        if make_default:
            set_key("profile.default", name)
            apply_profile_to_defaults(name)
        payload = {"ok": True, "profile": {"name": name, **saved}, "default": make_default}
        _emit(
            ctx,
            payload,
            Panel(
                f"Saved profile '{name}'\nDomain: {domain or '-'}  DC: {dc_ip or '-'}  Opsec: {opsec}",
                title="Profile saved",
            ),
        )

    @profile_app.command("use")
    def profile_use(ctx: typer.Context, name: str = typer.Argument(...)) -> None:
        """Activate a profile as the default for subsequent commands."""
        from adaf_attack.core.profiles import apply_profile_to_defaults, get_profile
        from adaf_attack.core.user_config import set_key

        profile = get_profile(name)
        if profile is None:
            error = ActionableError(
                "UNKNOWN_PROFILE",
                f"Unknown profile: {name}",
                "Run `adaf-attack profile list` to see saved profiles.",
                suggested_command="adaf-attack profile list",
            )
            _emit_error(ctx, error)
            raise typer.Exit(code=error.exit_code)
        set_key("profile.default", name)
        applied = apply_profile_to_defaults(name)
        _emit(
            ctx,
            {"ok": True, "profile": {"name": name, **profile}, "config": applied},
            Panel(
                f"Active profile: {name}\nDomain: {profile.get('domain') or '-'} @ {profile.get('dc_ip') or '-'}\nOpsec: {profile.get('opsec_profile') or 'balanced'}",
                title="Profile activated",
            ),
        )

    @profile_app.command("delete")
    def profile_delete(ctx: typer.Context, name: str = typer.Argument(...)) -> None:
        """Delete a saved profile."""
        from adaf_attack.core.profiles import delete_profile
        from adaf_attack.core.user_config import get_key, load_user_config, save_user_config

        if not delete_profile(name):
            error = ActionableError(
                "UNKNOWN_PROFILE",
                f"Unknown profile: {name}",
                "Run `adaf-attack profile list` to see saved profiles.",
                suggested_command="adaf-attack profile list",
            )
            _emit_error(ctx, error)
            raise typer.Exit(code=error.exit_code)
        if get_key("profile.default") == name:
            data = load_user_config()
            data.pop("profile.default", None)
            save_user_config(data)
        _emit(
            ctx, {"ok": True, "deleted": name}, Panel(f"Deleted profile '{name}'", title="Profile")
        )

    @profile_app.command("default")
    def profile_default(
        ctx: typer.Context,
        name: str | None = typer.Argument(None, help="Profile name; omit to clear default."),
    ) -> None:
        """Set or clear the default profile."""
        from adaf_attack.core.profiles import get_profile
        from adaf_attack.core.user_config import (
            load_user_config,
            save_user_config,
            set_key,
        )

        if name is None:
            data = load_user_config()
            data.pop("profile.default", None)
            save_user_config(data)
            _emit(
                ctx,
                {"ok": True, "default": None},
                Panel("Default profile cleared", title="Profile"),
            )
            return
        if get_profile(name) is None:
            error = ActionableError(
                "UNKNOWN_PROFILE",
                f"Unknown profile: {name}",
                "Run `adaf-attack profile list` to see saved profiles.",
                suggested_command="adaf-attack profile list",
            )
            _emit_error(ctx, error)
            raise typer.Exit(code=error.exit_code)
        set_key("profile.default", name)
        _emit(
            ctx,
            {"ok": True, "default": name, "profile": get_profile(name)},
            Panel(f"Default profile: {name}", title="Profile"),
        )

    @app.command("demo", rich_help_panel="Setup & diagnostics")
    def demo_cmd(
        ctx: typer.Context,
        workspace: Path | None = typer.Option(
            None, "--workspace", help="Where to materialize the demo session."
        ),
    ) -> None:
        """Offline first-success path using packaged demo fixtures (no network)."""
        from adaf_attack.core.ux import session_findings_dashboard

        dest_root = workspace or (default_workspace_dir() / "demo")
        dest = dest_root / "demo-session"
        if dest.exists():
            import shutil

            shutil.rmtree(dest)
        from adaf_attack.demo import materialize_demo_session

        try:
            materialize_demo_session(dest)
        except (OSError, FileNotFoundError) as exc:
            error = ActionableError(
                "DEMO_FIXTURES_MISSING",
                f"Could not create the packaged demo session: {exc}",
                "Choose a writable workspace and rerun `adaf-attack demo`.",
                suggested_command="adaf-attack paths",
            )
            _emit_error(ctx, error)
            raise typer.Exit(code=error.exit_code) from exc
        from adaf_attack.core.journey import guide_recovery_command, quote_path

        dashboard = session_findings_dashboard(dest)
        next_guide = guide_recovery_command(workspace=dest_root, session=dest)
        payload = {
            "ok": True,
            "mode": "offline-demo",
            "session_path": str(dest),
            "dashboard": dashboard,
            "next_step": next_guide,
            "suggested_command": next_guide,
            "recovery_command": next_guide,
            "next_steps": [
                next_guide,
                f"adaf-attack session show --session {quote_path(dest)}",
            ],
        }
        human = Panel(
            "\n".join(
                [
                    "Offline demo session materialized (no network contact).",
                    f"Session: {dest}",
                    f"Findings: {dashboard.get('finding_count', 0)}",
                    f"Graph nodes/edges: {dashboard.get('graph', {}).get('nodes', 0)} / {dashboard.get('graph', {}).get('edges', 0)}",
                    f"Next: {next_guide}",
                ]
            ),
            title="ADAF-ATTACK demo",
        )
        _emit(ctx, payload, human)

    @app.command("start-demo", rich_help_panel="Setup & diagnostics")
    def start_demo_cmd(
        ctx: typer.Context,
        workspace: Path | None = typer.Option(
            None, "--workspace", help="Where to materialize the demo session."
        ),
    ) -> None:
        """Start the safe offline demo."""
        demo_cmd(ctx, workspace)

    @app.command("completions", rich_help_panel="Setup & diagnostics")
    def completions_cmd(
        ctx: typer.Context,
        shell: str = typer.Argument(
            "bash",
            help="bash | zsh | fish | powershell (ignored when --all is set)",
        ),
        emit_all: bool = typer.Option(
            False, "--all", help="Emit scripts for every supported shell."
        ),
        output_dir: Path | None = typer.Option(
            None,
            "--output-dir",
            help="Write scripts as adaf-attack.<shell> under this directory instead of stdout.",
        ),
    ) -> None:
        """Print (or write) shell completion scripts for adaf-attack."""
        from adaf_attack.core.completions import (
            SUPPORTED_SHELLS,
            completion_install_hint,
            generate_completion,
        )

        shells = list(SUPPORTED_SHELLS) if emit_all else [shell]

        scripts: dict[str, str] = {}
        for sh in shells:
            try:
                scripts[sh] = generate_completion(sh)
            except ValueError as exc:
                error = ActionableError(
                    "UNSUPPORTED_SHELL",
                    str(exc),
                    f"Choose one of: {', '.join(SUPPORTED_SHELLS)}",
                    suggested_command="adaf-attack completions bash",
                )
                _emit_error(ctx, error)
                raise typer.Exit(code=error.exit_code) from exc

        if output_dir is not None:
            output_dir.mkdir(parents=True, exist_ok=True)
            written: list[str] = []
            for sh, script in scripts.items():
                extension = {"bash": "bash", "zsh": "zsh", "fish": "fish", "powershell": "ps1"}[sh]
                path = output_dir / f"adaf-attack.{extension}"
                path.write_text(script, encoding="utf-8")
                written.append(str(path))
            payload = {
                "ok": True,
                "written": written,
                "install_hints": {sh: completion_install_hint(sh) for sh in shells},
            }
            _emit(
                ctx,
                payload,
                Panel(
                    "\n".join(f"wrote {p}" for p in written),
                    title="Completion scripts",
                ),
            )
            return

        if _json_mode(ctx):
            if emit_all:
                _emit(
                    ctx,
                    {
                        "ok": True,
                        "scripts": scripts,
                        "install_hints": {sh: completion_install_hint(sh) for sh in shells},
                    },
                    "",
                )
            else:
                _emit(
                    ctx,
                    {
                        "ok": True,
                        "shell": shell,
                        "script": scripts[shell],
                        "install_hint": completion_install_hint(shell),
                    },
                    "",
                )
            return

        if emit_all:
            for sh, script in scripts.items():
                typer.echo(f"# ---- {sh} ----")
                typer.echo(script)
                _console(ctx).print(
                    f"[dim]# Install hint ({sh}): {completion_install_hint(sh)}[/dim]"
                )
        else:
            typer.echo(scripts[shell])
            _console(ctx).print(f"[dim]# Install hint: {completion_install_hint(shell)}[/dim]")

    @session_app.command("show")
    def session_show(
        ctx: typer.Context,
        session: Path = typer.Option(..., "--session", help="Session directory to inspect."),
        severity: str | None = typer.Option(
            None, "--severity", help="Filter findings by severity."
        ),
        limit: int = typer.Option(50, "--limit"),
    ) -> None:
        """Show a richer findings dashboard for one session."""
        import json

        from adaf_attack.core.ux import session_findings_dashboard

        if not session.is_dir():
            error = error_for("SESSION_NOT_FOUND", details={"session": str(session)})
            _emit_error(ctx, error)
            raise typer.Exit(code=error.exit_code)
        dashboard = session_findings_dashboard(session, severity=severity, limit=limit)
        try:
            outcome = json.loads((session / "outcome.json").read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            outcome = None
        timeline: list[dict[str, Any]] = []
        events = session / "events.jsonl"
        if events.is_file():
            try:
                for line in events.read_text(encoding="utf-8").splitlines()[-25:]:
                    try:
                        item = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if isinstance(item, dict):
                        timeline.append(
                            {
                                "time": item.get("time") or item.get("timestamp"),
                                "event": item.get("event") or item.get("type") or "event",
                                "capability": item.get("capability"),
                            }
                        )
            except OSError:
                timeline = []
        payload = {
            "ok": True,
            **dashboard,
            "timeline": timeline,
            "outcome": outcome,
            "resume_command": f"adaf-attack session show --session {session}",
        }
        finding_count = dashboard.get("finding_count", 0)
        severity_counts = dashboard.get("severity") or {}
        severity_display = severity_counts if severity_counts else "none"
        lines = [
            f"Session: {dashboard.get('session_id')}",
            f"Created: {dashboard.get('created_at') or 'unknown'}",
            f"Findings: {finding_count}  Severity: {severity_display}",
            f"Graph: {dashboard.get('graph', {}).get('nodes', 0)} nodes / {dashboard.get('graph', {}).get('edges', 0)} edges",
            f"Outcome: {outcome.get('status')}  Rollback: {outcome.get('rollback', {}).get('status')}"
            if isinstance(outcome, dict)
            else "Outcome: not recorded",
            f"Detection: {outcome.get('detection', {}).get('status', 'not-recorded')}"
            if isinstance(outcome, dict)
            else "Detection: not recorded",
            f"Resume: adaf-attack session show --session {session}",
        ]
        if finding_count == 0:
            from adaf_attack.core.journey import empty_surface_guidance

            empty = empty_surface_guidance(
                "findings",
                workspace=session.parent,
                session=session,
                doctor=doctor_payload("user-readiness"),
            )
            payload["empty_state"] = empty
            payload["next_step"] = empty["next_command"]
            payload["suggested_command"] = empty["next_command"]
            lines.append(f"Empty: {empty['message']}")
            lines.append(f"Next: {empty['next_command']}")
        titles = dashboard.get("titles") or []
        if titles:
            lines.append("Titles:")
            for title in titles[:10]:
                lines.append(f"  - {title}")
        top_paths = dashboard.get("top_paths") or []
        if top_paths:
            lines.append("Top paths:")
            for path_item in top_paths[:5]:
                if isinstance(path_item, dict):
                    nodes = path_item.get("path") or []
                    short = " -> ".join(str(x).split("@")[0] for x in nodes[:6])
                    lines.append(f"  score={path_item.get('score', '?')}  {short}")
        if timeline:
            lines.append("Timeline:")
            for item in timeline[-5:]:
                label = item.get("event") or "event"
                cap = f" ({item['capability']})" if item.get("capability") else ""
                lines.append(f"  - {item.get('time') or 'unknown'}: {label}{cap}")
        human = Panel("\n".join(lines), title="Session findings dashboard")
        _emit(ctx, payload, human)

    @session_app.command("access")
    def session_access(
        ctx: typer.Context,
        session: Path = typer.Option(..., "--session", help="Session directory to inspect."),
    ) -> None:
        """Show safe identity, authentication, and credential-context metadata."""
        from adaf_attack.core.access_context import session_access_context

        if not session.is_dir():
            error = error_for("SESSION_NOT_FOUND", details={"session": str(session)})
            _emit_error(ctx, error)
            raise typer.Exit(code=error.exit_code)
        payload = session_access_context(session)
        identities = payload["identities"]
        human = Panel(
            "Recommended identity: "
            + str(payload["recommended_identity"] or "not recorded")
            + "\n\n"
            + (
                "\n".join(
                    f"{item['identity']} — {', '.join(item['auth_modes']) or 'auth not recorded'}"
                    for item in identities
                )
                or "No identities recorded."
            )
            + f"\n\nCredential artifacts: {len(payload['credential_artifacts'])}\n{payload['safety']}",
            title="Session access context",
        )
        _emit(ctx, payload, human)
