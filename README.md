# Proactive Pipeline Security

A local-first Git pre-commit security gate for Python and Bash projects. It examines
the *staged* version of changed files, reports likely OWASP-aligned issues, and can
optionally submit a bounded diff to an LLM for contextual review.

## Design

1. **Deterministic rules run first.** They are fast, private, and block high-signal
   problems such as hard-coded secrets, `eval`, and shell injection risks.
2. **The LLM reviewer is opt-in.** It runs only when `--llm` is supplied. Review
   the staged content before enabling it, because source code leaves the machine.
3. **The hook reads Git's index.** The feedback matches what will be committed, not
   un-staged edits in the working tree.

## Quick start

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
PYTHONPATH=src python3 -m pipeline_security --staged
```

Install the versioned hook configuration after installing `pre-commit` (for example,
in a project virtual environment):

```bash
python3 -m venv .venv
.venv/bin/python -m pip install pre-commit
.venv/bin/pre-commit install
.venv/bin/pre-commit run --all-files
```

## Use in another repository

PPS is a [pre-commit](https://pre-commit.com/) plugin. After a release tag is
published, add the following to the consuming repository's
`.pre-commit-config.yaml` (replace the revision with the release you want to
use):

```yaml
repos:
  - repo: https://github.com/lishihan229/proactive-pipeline-security
    rev: v0.1.0
    hooks:
      - id: pipeline-security
```

Install the hook once in that repository:

```bash
python3 -m pip install --user pre-commit
pre-commit install
```

Every subsequent `git commit` will scan the repository's staged Python and
Bash/Shell files. Developers can also run the check manually:

```bash
pre-commit run pipeline-security --all-files
```

Use an immutable release tag or commit SHA for `rev`; do not use a moving branch
such as `main` for team policy.

## Optional LLM review

The LLM integration is deliberately provider-neutral. Configure an OpenAI-compatible
chat-completions endpoint, keeping credentials out of Git:

```bash
export LLM_API_KEY='...'
export LLM_API_URL='https://your-provider.example/v1/chat/completions'
export LLM_MODEL='your-model'
```

Run it explicitly with `PYTHONPATH=src python3 -m pipeline_security --staged --llm`.
It is advisory only; deterministic rules enforce blocking policy. The tool redacts
simple assignment-style credentials and caps the sent content at 12,000 characters,
but review the exact staged diff and use an approved endpoint before enabling it on
proprietary code.
