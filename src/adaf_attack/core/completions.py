"""Shell completion script generation for ADAF-ATTACK."""

from __future__ import annotations

SUPPORTED_SHELLS = ("bash", "zsh", "fish", "powershell")


def _capability_ids() -> list[str]:
    try:
        import adaf_attack.capabilities  # noqa: F401
        from adaf_attack.core.registry import capability_registry

        return capability_registry.ids()
    except Exception:  # noqa: BLE001
        return []


def generate_completion(shell: str) -> str:
    """Return a completion script for the requested shell."""
    shell = shell.lower().strip()
    if shell not in SUPPORTED_SHELLS:
        raise ValueError(f"Unsupported shell: {shell}. Choose from: {', '.join(SUPPORTED_SHELLS)}")
    caps = " ".join(_capability_ids())
    top_commands = (
        "doctor check list-capabilities paths capability-help plan review tour help-me search sessions cleanup "
        "run rank-paths start engagement config capability session path profile demo start-demo favorites targets "
        "errors completions credential-exposure bloodhound-reconcile trust-correlation "
        "delegation-validation adcs-validation campaign-compose forest-campaign campaign-run "
        "purple-handoff gpo-impact-plan coercion-fixtures workflow-profiles"
    )
    if shell == "bash":
        return _bash(top_commands, caps)
    if shell == "zsh":
        return _zsh(top_commands, caps)
    if shell == "fish":
        return _fish(top_commands, caps)
    return _powershell(top_commands, caps)


def _bash(commands: str, caps: str) -> str:
    return f"""# ADAF-ATTACK bash completion
_adaf_attack_completion() {{
  local cur prev
  COMPREPLY=()
  cur=\"${{COMP_WORDS[COMP_CWORD]}}\"
  prev=\"${{COMP_WORDS[COMP_CWORD-1]}}\"
  local cmds=\"{commands}\"
  local caps=\"{caps}\"
  case \"${{prev}}\" in
    run|plan|capability-help|capability)
      COMPREPLY=( $(compgen -W \"${{caps}}\" -- \"${{cur}}\") )
      return 0
      ;;
    --format)
      COMPREPLY=( $(compgen -W \"human json\" -- \"${{cur}}\") )
      return 0
      ;;
    completions)
      COMPREPLY=( $(compgen -W \"bash zsh fish powershell\" -- \"${{cur}}\") )
      return 0
      ;;
    profile)
      COMPREPLY=( $(compgen -W \"list show set use delete default\" -- \"${{cur}}\") )
      return 0
      ;;
  esac
  if [[ ${{COMP_CWORD}} -eq 1 ]]; then
    COMPREPLY=( $(compgen -W \"${{cmds}}\" -- \"${{cur}}\") )
  fi
}}
complete -F _adaf_attack_completion adaf-attack
"""


def _zsh(commands: str, caps: str) -> str:
    return f"""#compdef adaf-attack
# ADAF-ATTACK zsh completion
_adaf_attack() {{
  local -a commands capabilities
  commands=({" ".join(f"'{c}'" for c in commands.split())})
  capabilities=({" ".join(f"'{c}'" for c in caps.split()) if caps else ""})
  _arguments \\
    '1:command:->cmds' \\
    '*::arg:->args'
  case $state in
    cmds) _describe 'command' commands ;;
    args)
      case $words[1] in
        run|plan|capability-help) _describe 'capability' capabilities ;;
        completions) _values shell bash zsh fish powershell ;;
        profile) _values action list show set use delete default ;;
      esac
      ;;
  esac
}}
compdef _adaf_attack adaf-attack
"""


def _fish(commands: str, caps: str) -> str:
    lines = [
        "# ADAF-ATTACK fish completion",
        "complete -c adaf-attack -f",
    ]
    for cmd in commands.split():
        lines.append(f"complete -c adaf-attack -n '__fish_use_subcommand' -a '{cmd}'")
    for cap in caps.split():
        lines.append(
            f"complete -c adaf-attack -n '__fish_seen_subcommand_from run plan capability-help' -a '{cap}'"
        )
    lines.append(
        "complete -c adaf-attack -n '__fish_seen_subcommand_from completions' -a 'bash zsh fish powershell'"
    )
    lines.append(
        "complete -c adaf-attack -n '__fish_seen_subcommand_from profile' -a 'list show set use delete default'"
    )
    return "\n".join(lines) + "\n"


def _powershell(commands: str, caps: str) -> str:
    cmd_list = ", ".join(f"'{c}'" for c in commands.split())
    cap_list = ", ".join(f"'{c}'" for c in caps.split()) if caps else ""
    return f"""# ADAF-ATTACK PowerShell completion
Register-ArgumentCompleter -CommandName adaf-attack -ScriptBlock {{
  param($wordToComplete, $commandAst, $cursorPosition)
  $commands = @({cmd_list})
  $capabilities = @({cap_list})
  $tokens = $commandAst.CommandElements | ForEach-Object {{ $_.ToString() }}
  if ($tokens.Count -le 2) {{
    $commands | Where-Object {{ $_ -like \"$wordToComplete*\" }} | ForEach-Object {{
      [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
    }}
  }} elseif ($tokens[1] -in @('run','plan','capability-help')) {{
    $capabilities | Where-Object {{ $_ -like \"$wordToComplete*\" }} | ForEach-Object {{
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
