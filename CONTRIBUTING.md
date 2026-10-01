# Contributing to EDR4

EDR4 uses scoped Conventional Commits so that team members can understand a
change without opening the diff.

## Commit-message format

```text
type(scope): imperative summary
```

Use a lowercase type and scope. Begin the summary with a lowercase imperative
verb such as `add`, `handle`, `prevent`, `update`, or `remove`. Do not end the
summary with a full stop.

Examples appropriate for this repository:

```text
feat(morgan): detect sanitized URL SQLi indicators
fix(console): suppress routine metrics outside verbose mode
refactor(storage): isolate metric persistence policy
docs(code): add beginner-focused code walkthrough
chore(deps): update psutil requirement
```

## Types

Use the following commit types:

| Type | Use |
|---|---|
| `feat` | New collection, detection, storage, or operator-facing behavior |
| `fix` | Correction of faulty or unsafe behavior |
| `refactor` | Internal restructuring with no intended behavior change |
| `docs` | Documentation and code-comment changes only |
| `chore` | Dependency, repository, or routine maintenance work |

For test-only maintenance, use an appropriate scoped message such as
`chore(tests): add coverage for journal retry handling`. Tests that support a
feature or fix normally belong in the same commit as that change.

## Scopes

Choose the smallest stable component name that describes the change. Common
EDR4 scopes include:

- `morgan`, `journal`, `process`, and `system` for collectors;
- `detection`, `storage`, `console`, `config`, and `privacy` for shared behavior;
- `scripts`, `tests`, `docs`, `code`, and `deps` for supporting work.

Additional scopes are acceptable when they identify a clear project component.
Avoid personal names, issue descriptions, or temporary branch names as scopes.

## Detailed commit bodies

A small change may use only the subject line. For a larger change, leave one
blank line and add concise capitalized `-` bullets:

```text
feat(detection): add repeated authentication failure rule

- Added per-source windows for authentication-like 401 responses
- Added configurable thresholds and finding cooldowns
- Added tests for window expiry and repeated-alert suppression
```

The subject explains the outcome. Body bullets record material implementation,
safety, migration, or validation details. Do not repeat every changed filename.

## Before committing

Review exactly what will be committed and run the project checks:

```bash
git status --short
git diff --cached
.venv/bin/python -m unittest discover -s tests -v
git diff --check
```

Never place passwords, tokens, cookies, authorization values, request bodies,
or other secrets in a commit message, staged file, fixture, or example.

Do not rewrite or force-push commits already shared with the team unless all
affected contributors have explicitly coordinated the rewrite.
