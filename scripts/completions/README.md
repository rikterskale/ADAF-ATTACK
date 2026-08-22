# Shell completion scripts

These scripts are generated on demand by the CLI. The maintained source of
truth is the running installation:

```bash
adaf-attack completions --all --output-dir scripts/completions
```

Regenerate whenever a CLI command is added or renamed. Do **not** commit
generated `adaf-attack.<shell>` files here — the shell installers already
run `adaf-attack --install-completion <shell>` at install time.

## Manual install

| Shell      | Command                                            |
|------------|----------------------------------------------------|
| bash       | `adaf-attack --install-completion bash`            |
| zsh        | `adaf-attack --install-completion zsh`             |
| fish       | `adaf-attack --install-completion fish`            |
| PowerShell | `adaf-attack --install-completion powershell`      |

## Offline packaging

To ship completion scripts alongside an air-gapped release wheelhouse:

```bash
adaf-attack completions --all --output-dir ./completions
```

Then transfer `./completions/` with the wheelhouse.
