"""Shell completion script generation for ADAF-ATTACK."""

from __future__ import annotations

SUPPORTED_SHELLS = ("bash", "zsh", "fish", "powershell")
OUTPUT_FORMATS = ("human", "json", "summary", "table", "beginner")


def _capability_ids() -> list[str]:
    try:
        import adaf_attack.capabilities  # noqa: F401
        from adaf_attack.core.registry import capability_registry

        return capability_registry.ids()
    except Exception:  # noqa: BLE001
        return []


def _profile_names() -> list[str]:
    try:
        from adaf_attack.core.profiles import list_profiles

        return [str(item["name"]) for item in list_profiles() if item.get("name")]
    except Exception:  # noqa: BLE001
        return []


def _session_ids() -> list[str]:
    try:
        from adaf_attack.core.paths import default_workspace_dir

        root = default_workspace_dir()
        if not root.is_dir():
            return []
        sessions = [
            path.name
            for path in root.iterdir()
            if path.is_dir() and (path / "session.json").is_file()
        ]
        return sorted(sessions, reverse=True)[:100]
    except Exception:  # noqa: BLE001
        return []


def generate_completion(shell: str) -> str:
    """Return a completion script for the requested shell."""
    shell = shell.lower().strip()
    if shell not in SUPPORTED_SHELLS:
        raise ValueError(f"Unsupported shell: {shell}. Choose from: {', '.join(SUPPORTED_SHELLS)}")
    caps = " ".join(_capability_ids())
    profiles = " ".join(_profile_names())
    sessions = " ".join(_session_ids())
    formats = " ".join(OUTPUT_FORMATS)
    top_commands = (
        "home doctor check list-capabilities paths capability-help plan review tour help-me "
        "command search sessions cleanup finding run rank-paths start engagement config "
        "capability session path profile demo start-demo favorites targets errors completions "
        "credential-exposure bloodhound-reconcile trust-correlation delegation-validation "
        "adcs-validation campaign-compose forest-campaign campaign-run purple-handoff "
        "gpo-impact-plan coercion-fixtures workflow-profiles start-here explain what-next "
        "credential-inventory tool cockpit what-if timeline copilot collaboration"
    )
    if shell == "bash":
        return _bash(top_commands, caps, profiles, sessions, formats)
    if shell == "zsh":
        return _zsh(top_commands, caps, profiles, sessions, formats)
    if shell == "fish":
        return _fish(top_commands, caps, profiles, sessions, formats)
    return _powershell(top_commands, caps, profiles, sessions)


def _bash(commands: str, caps: str, profiles: str, sessions: str, formats: str) -> str:
    return f"""# ADAF-ATTACK bash completion
_adaf_attack_completion() {{
  local cur prev
  COMPREPLY=()
  cur=\"${{COMP_WORDS[COMP_CWORD]}}\"
  prev=\"${{COMP_WORDS[COMP_CWORD-1]}}\"
  local cmds=\"{commands}\"
  local caps=\"{caps}\"
  local profiles=\"{profiles}\"
  local sessions=\"{sessions}\"
  local formats=\"{formats}\"
  case \"${{prev}}\" in
    run|plan|capability-help|capability|command)
      COMPREPLY=( $(compgen -W \"${{caps}}\" -- \"${{cur}}\") )
      return 0
      ;;
    --format)
      COMPREPLY=( $(compgen -W \"${{formats}}\" -- \"${{cur}}\") )
      return 0
      ;;
    --session)
      COMPREPLY=( $(compgen -W \"${{sessions}}\" -- \"${{cur}}\") )
      return 0
      ;;
    completions)
      COMPREPLY=( $(compgen -W \"bash zsh fish powershell\" -- \"${{cur}}\") )
      return 0
      ;;
    session)
      COMPREPLY=( $(compgen -W \"list show diff resume\" -- \"${{cur}}\") )
      return 0
      ;;
    profile)
      COMPREPLY=( $(compgen -W \"list show set use delete default\" -- \"${{cur}}\") )
      return 0
      ;;
    show|use|delete|default)
      COMPREPLY=( $(compgen -W \"${{profiles}}\" -- \"${{cur}}\") )
      return 0
      ;;
    finding)
      COMPREPLY=( $(compgen -W \"explain remediate triage\" -- \"${{cur}}\") )
      return 0
      ;;
  esac
  if [[ ${{COMP_CWORD}} -eq 1 ]]; then
    COMPREPLY=( $(compgen -W \"${{cmds}}\" -- \"${{cur}}\") )
  fi
}}
complete -F _adaf_attack_completion adaf-attack
"""


def _zsh(commands: str, caps: str, profiles: str, sessions: str, formats: str) -> str:
    return f"""#compdef adaf-attack
# ADAF-ATTACK zsh completion
_adaf_attack() {{
  local -a commands capabilities profiles sessions formats
  commands=({" ".join(f"'{c}'" for c in commands.split())})
  capabilities=({" ".join(f"'{c}'" for c in caps.split()) if caps else ""})
  profiles=({" ".join(f"'{c}'" for c in profiles.split()) if profiles else ""})
  sessions=({" ".join(f"'{c}'" for c in sessions.split()) if sessions else ""})
  formats=({" ".join(f"'{c}'" for c in formats.split())})
  _arguments \\
    '1:command:->cmds' \\
    '*::arg:->args'
  case $state in
    cmds) _describe 'command' commands ;;
    args)
      case $words[1] in
        run|plan|capability-help|command) _describe 'capability' capabilities ;;
        completions) _values shell bash zsh fish powershell ;;
        profile) _values action list show set use delete default ;;
        finding) _values action explain remediate ;;
      esac
      if [[ $words[CURRENT-1] == '--format' ]]; then _describe 'format' formats; fi
      if [[ $words[CURRENT-1] == '--session' ]]; then _describe 'session' sessions; fi
      ;;
  esac
}}
compdef _adaf_attack adaf-attack
"""


def _fish(commands: str, caps: str, profiles: str, sessions: str, formats: str) -> str:
    lines = [
        "# ADAF-ATTACK fish completion",
        "complete -c adaf-attack -f",
    ]
    for cmd in commands.split():
        lines.append(f"complete -c adaf-attack -n '__fish_use_subcommand' -a '{cmd}'")
    for cap in caps.split():
        lines.append(
            "complete -c adaf-attack "
            "-n '__fish_seen_subcommand_from run plan capability-help command' "
            f"-a '{cap}'"
        )
    for profile in profiles.split():
        lines.append(
            f"complete -c adaf-attack -n '__fish_seen_subcommand_from profile' -a '{profile}'"
        )
    for session in sessions.split():
        lines.append(f"complete -c adaf-attack -l session -a '{session}'")
    lines.append(
        "complete -c adaf-attack -n '__fish_seen_subcommand_from completions' "
        "-a 'bash zsh fish powershell'"
    )
    lines.append(f"complete -c adaf-attack -l format -a '{formats}'")
    lines.append(
        "complete -c adaf-attack -n '__fish_seen_subcommand_from finding' "
        "-a 'explain remediate'"
    )
    lines.append(
        "complete -c adaf-attack -n '__fish_seen_subcommand_from profile' "
        "-a 'list show set use delete default'"
    )
    return "\n".join(lines) + "\n"


def _powershell(commands: str, caps: str, profiles: str, sessions: str) -> str:
    cmd_list = ", ".join(f"'{c}'" for c in commands.split())
    cap_list = ", ".join(f"'{c}'" for c in caps.split()) if caps else ""
    profile_list = ", ".join(f"'{c}'" for c in profiles.split()) if profiles else ""
    session_list = ", ".join(f"'{c}'" for c in sessions.split()) if sessions else ""
    format_list = ", ".join(f"'{c}'" for c in OUTPUT_FORMATS)
    return f"""# ADAF-ATTACK PowerShell completion
Register-ArgumentCompleter -CommandName adaf-attack -ScriptBlock {{
  param($wordToComplete, $commandAst, $cursorPosition)
  $commands = @({cmd_list})
  $capabilities = @({cap_list})
  $profiles = @({profile_list})
  $sessions = @({session_list})
  $formats = @({format_list})
  $tokens = $commandAst.CommandElements | ForEach-Object {{ $_.ToString() }}
  if ($tokens.Count -le 2) {{
    $commands | Where-Object {{ $_ -like \"$wordToComplete*\" }} | ForEach-Object {{
      [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
    }}
  }} elseif ($tokens[1] -in @('run','plan','capability-help','command')) {{
    $capabilities | Where-Object {{ $_ -like \"$wordToComplete*\" }} | ForEach-Object {{
      [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
    }}
  }} elseif ($tokens[-2] -eq '--format') {{
    $formats | Where-Object {{ $_ -like \"$wordToComplete*\" }} | ForEach-Object {{
      [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
    }}
  }} elseif ($tokens[-2] -eq '--session') {{
    $sessions | Where-Object {{ $_ -like \"$wordToComplete*\" }} | ForEach-Object {{
      [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
    }}
  }} elseif ($tokens[1] -eq 'profile') {{
    $profiles | Where-Object {{ $_ -like \"$wordToComplete*\" }} | ForEach-Object {{
      [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
    }}
  }}
}}
"""


def completion_install_hint(shell: str) -> str:
    if shell == "bash":
        return "Save to ~/.local/share/bash-completion/completions/adaf-attack or source the script in ~/.bashrc"
    if shell == "zsh":
        return (
            "Save as a file on your fpath (e.g. ~/.zsh/completions/_adaf-attack) and run compinit"
        )
    if shell == "fish":
        return "Save to ~/.config/fish/completions/adaf-attack.fish"
    return "Dot-source the script in your PowerShell profile"
