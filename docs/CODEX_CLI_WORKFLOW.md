# Using Codex safely with ADAF-ATTACK: beginner guide

This guide is for someone with no computer experience. It explains how to ask
Codex to make a small change, check that work, and avoid running the toolkit
against a real network.

## The most important rule

ADAF-ATTACK can contact systems and can change Active Directory settings.
For normal development, work **offline only**. Codex may read and edit the
project files and run tests, but it must not scan, log in to, authenticate to,
or contact a real computer or network.

If Codex asks to access the internet, install software, use GitHub, write
outside this project, or contact a target, do not approve it. Ask an
experienced teammate first.

## Small dictionary

| Word | Meaning |
| --- | --- |
| Folder | A place on your computer that holds files. |
| Repository | The project folder and its change history. |
| Terminal | A text window where you type commands. On Windows, use PowerShell. |
| Command | Text you enter in the terminal to tell the computer what to do. |
| Git | The tool that records project changes. |
| Branch | A separate, safe line of work that does not change the main version. |
| Test | An automatic check that tells us whether code still works. |

## Before you start

You need a Windows computer with ADAF-ATTACK, Python, and Codex CLI already
installed by a team member. You also need a small, specific task. Good examples
are “improve this error message” or “add a test for this command.” Do not begin
with “improve everything.”

## 1. Open PowerShell

1. Click the **Start** button.
2. Type `PowerShell`.
3. Click **Windows PowerShell**.

Copy the command below into the window and press **Enter**:

```powershell
cd C:\path\to\ADAF-ATTACK
```

This moves PowerShell into the ADAF-ATTACK project folder. If you see a red
error, stop and ask the person who installed the project where it is located.

## 2. Check for somebody else's work

Copy, paste, and run:

```powershell
git status
```

- If it says `working tree clean`, there are no local edits waiting.
- If it lists changed or untracked files, someone may already be working here.

Do not delete, move, overwrite, or “clean up” those files. Ask their owner or
an experienced teammate before continuing. Never use `git reset`, `git clean`,
or `git checkout --`; these can discard work.

## 3. Create a safe branch

A branch gives your task its own separate name. For example, run:

```powershell
git switch -c codex/better-error-message
```

You can replace `better-error-message` with a few lowercase words separated
by hyphens. Keep `codex/` at the beginning. If Git says that branch already
exists, choose a different name; do not force anything.

## 4. Start Codex

Run:

```powershell
codex --sandbox workspace-write --ask-for-approval on-request
```

This lets Codex edit files inside this project folder. It should ask before it
tries to do something broader. Never use `--yolo` or
`--dangerously-bypass-approvals-and-sandbox`; those remove protections.

## 5. Tell Codex what to do

Copy this complete message into Codex. Replace only the text in square
brackets with your small task.

```text
Work only in the current ADAF-ATTACK project folder.

MY TASK

[Write one small change here. Example: Improve the error message shown when an
engagement file is missing its allowed_targets field.]

IMPORTANT SAFETY RULES

- Preserve changes that were already in the folder before this task.
- Do not commit, push, publish, deploy, or create a pull request.
- This is offline development. Do not contact a network or a real computer.
- Do not scan, authenticate, log in, coerce, relay, request Kerberos tickets,
  dump credentials, or make Active Directory changes.
- Use existing tests, fixtures, mocks, and saved example session files only.
- Keep the current safety features: engagement target and capability scope,
  approval tokens, --force requirements, redaction, audit logging, and cleanup.
- Do not lower test coverage or disable tests, linting, type checking, or
  security checks to make a result look successful.

HOW TO WORK

First, read the relevant code, tests, documentation, and CI workflow. Explain
your short plan in plain language, then make only the smallest change needed.
Add or update tests for changed behavior.

Run the smallest related test. If it fails, read the error, explain the cause
plainly, fix the cause, and run the test again. Then run the relevant available
project checks.

WHEN FINISHED, SHOW ME

- What changed, in plain language
- Each file changed
- Each check run and whether it passed
- Anything that could not be checked and why
- git status --short
- git diff --stat

Do not say a check passed unless you actually ran it successfully.
```

## 6. Read permission requests before approving them

Codex can normally read, test, and edit files inside ADAF-ATTACK. Stop and ask
for help before approving a request that:

- downloads or installs packages from the internet;
- uses GitHub, sends data, pushes code, or opens a pull request;
- writes outside the ADAF-ATTACK folder;
- runs against an IP address, hostname, domain controller, or another target;
- requests passwords, keys, certificates, or secrets; or
- deletes files or uses `git reset`, `git clean`, or a force option.

If you are unsure, do not approve it. A teammate can review the request.

## 7. Understand what Codex is doing

You may see Codex read a Python file, run one small test, edit files, rerun the
test, and then run broader checks. This is the “edit-test-fix” loop.

A failed test is not automatically bad. What matters is that Codex explains the
cause, makes a focused correction, and runs the check again. If it stops after
a failure, paste this message:

```text
Please continue. Read the full test failure, explain the root cause in plain
language, make the smallest correct fix, and rerun the failed check. Do not
weaken a test or safety check. When it passes, run the relevant broader checks.
```

## 8. Check the result

When Codex is finished, open another PowerShell window in the ADAF-ATTACK
folder and run:

```powershell
git status
git diff --stat
git diff --check
git diff
```

- `git status` lists changed and new files.
- `git diff --stat` gives a short count of changes.
- `git diff --check` looks for accidental whitespace mistakes.
- `git diff` shows every change. Ask an experienced teammate to review it if
  it affects safety controls or operational behavior.

Do not commit just because Codex says it is done.

## 9. Ask for a separate review

Run:

```powershell
codex review --uncommitted
```

This asks Codex to look for mistakes in the uncommitted changes without
changing files. If it finds a real problem, ask Codex to make the smallest
correction, add a test if needed, and rerun the affected checks.

## 10. Hand it to a reviewer

For a beginner, the safest final step is to give the branch and Codex’s summary
to an experienced teammate. They can inspect the change, confirm the tests, and
decide whether it is ready to commit.

Never put passwords, API keys, Kerberos tickets, hashes, certificates, session
vault contents, or client evidence into Codex prompts, Git commits, or chat
messages.

## Do not do these things

- Do not run ADAF-ATTACK against a real target unless a live, authorized
  engagement explicitly requires it and an experienced operator directs you.
- Do not approve a command simply because it says it will fix an error.
- Do not use a command you do not understand if it could delete files, contact
  a network, install software, or publish code.
- Do not lower coverage, skip tests, or turn off a security check.
- Do not commit all files at once with `git add -A`.

The project has automated tests, formatting, type, security, packaging, and
Windows/Linux checks. Codex can run the checks available on your computer;
GitHub CI performs the final cross-platform check after a reviewer submits the
work. When any step is unclear, stop and ask for help. Stopping safely is
better than guessing.
