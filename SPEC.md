# Proactive Pipeline Security — Product Specification

## 1. Purpose

Proactive Pipeline Security (PPS) is a local-first security gate for Git
commits. It reviews the staged version of application code before it is
committed, catches high-signal security mistakes early, and gives developers a
clear remediation path.

The first release targets Python and Bash/Shell projects. It is intended to be
quick to run, understandable, safe to adopt incrementally, and usable without
sending source code to a third party.

## 2. Problem

Security issues such as committed credentials, dynamic code execution, unsafe
shell usage, and SQL injection patterns often reach repositories because review
happens late or relies on developers remembering every secure-coding rule.

Existing tools can be difficult to configure, noisy, cloud-dependent, or
focused only on CI. PPS provides an inexpensive feedback loop at commit time
while leaving final policy decisions with each team.

## 3. Users

- Individual developers who want a lightweight local security check.
- Small teams adding a consistent pre-commit security baseline.
- Application-security engineers who need a transparent, extensible rule set.

## 4. Goals

- Scan staged Python, `.sh`, and `.bash` files before a commit.
- Detect a small set of common, high-value OWASP-aligned risks.
- Show the file, line, severity, rule identifier, and safe remediation.
- Block commits when deterministic blocking rules find an issue.
- Work offline by default and avoid transmitting source code.
- Offer an explicitly enabled, advisory LLM review for contextual feedback.
- Integrate with `pre-commit` and be runnable directly from the command line.

## 5. Non-goals (MVP)

- Proving that code is secure or replacing a professional application-security
  review.
- Performing runtime, dependency, container, infrastructure, or secret-history
  scanning.
- Automatically fixing source code.
- Enforcing LLM findings as a commit-blocking policy.
- Supporting every programming language in the first release.

## 6. Current MVP Behavior

### Inputs

PPS obtains the list and contents of added, copied, modified, or renamed files
from Git's index. It only considers files ending in `.py`, `.sh`, or `.bash`.
Consequently, findings reflect the next commit rather than unrelated working
tree edits.

### Deterministic rules

Each line is checked against explainable rules. The current rules identify:

| Rule | Severity | Risk |
| --- | --- | --- |
| `A02-hardcoded-secret` | high | Assignment-style API keys, secrets, passwords, and tokens |
| `A03-code-injection` | high | Python `eval` or `exec` |
| `A03-shell-injection` | high | `subprocess` calls with `shell=True` |
| `A03-sql-injection` | high | SQL execution using an f-string |
| `A05-unsafe-deserialization` | high | Potentially unsafe `yaml.load` |
| `A05-debug-mode` | medium | Debug mode enabled |
| `A02-weak-crypto` | medium | MD5 or SHA-1 use |
| `A03-bash-command-substitution` | medium | Bash `eval` or legacy backticks |

A line ending with or containing `# pps: ignore` is skipped. This is an
escape hatch for known-safe code; it should be used sparingly and reviewed.

### Command-line interface

```text
python -m pipeline_security --staged
python -m pipeline_security --staged --llm
```

The scanner prints one finding per line in this form:

```text
path:line: SEVERITY rule-id: remediation message
```

It exits with status `1` when deterministic findings exist and `0` when none
exist. The `--staged` option documents the intended mode; scanning is currently
always staged-content based.

### Pre-commit integration

The versioned `.pre-commit-config.yaml` invokes:

```text
PYTHONPATH=src python3 -m pipeline_security --staged
```

The hook receives no filenames because PPS independently reads the Git index.

## 7. LLM Review and Privacy

LLM review is advisory only and must be started explicitly with `--llm`. The
reviewer calls an OpenAI-compatible chat-completions endpoint configured with
`LLM_API_KEY`, `LLM_API_URL`, and `LLM_MODEL`.

Before transmission, PPS redacts simple quoted assignment-style credentials and
caps submitted content at 12,000 characters. This is a best-effort guard, not a
guarantee that proprietary or sensitive data is absent. Users must inspect the
staged changes and use an approved endpoint before enabling the option.

LLM unavailable or malformed-response cases return advisory text and must not
change the deterministic scan's pass/fail outcome.

## 8. Architecture

```text
Git index -> git.py -> staged files and content -> rules.py -> findings -> CLI exit code
                                               \\-> llm.py (only with --llm) -> advisory output
```

- `git.py`: reads staged file names and content through Git.
- `rules.py`: owns finding data, rule IDs, severities, regular expressions, and
  inline suppression handling.
- `cli.py`: parses options, reports findings, and chooses the process exit code.
- `llm.py`: redacts basic secrets, constructs the review request, and handles
  provider errors.

## 9. Configuration and Policy (planned)

PPS should add project-level configuration in `pyproject.toml` or a dedicated
configuration file. It should support:

- minimum blocking severity;
- enabled and disabled rule IDs;
- reviewed, expiring suppressions with a reason;
- file/path exclusions;
- organization-approved LLM endpoint policy;
- JSON and SARIF output settings.

Until this exists, policy is defined by the bundled rules and inline
`# pps: ignore` suppressions.

## 10. Quality and Acceptance Criteria

The MVP is acceptable when:

- a staged file containing each supported unsafe pattern produces the expected
  rule ID, severity, and line number;
- safe environment-variable credential retrieval does not trigger the
  hard-coded-secret rule;
- an ignored line produces no finding;
- a finding returns exit status `1`, and a clean staged set returns `0`;
- unstaged edits do not alter scan results;
- the pre-commit hook runs from a fresh supported Python environment;
- LLM review is not contacted unless `--llm` is supplied;
- credentials matching the supported assignment pattern are redacted before an
  LLM request is built;
- network and malformed-response failures do not crash the scanner.

## 11. Roadmap

### Milestone 1 — Reliable local scanner

- Replace Python regex checks with AST-aware rules where appropriate.
- Add integration tests that create a temporary Git repository and verify index
  versus working-tree behavior.
- Add column/snippet context and stable output tests.
- Clarify or remove the unused `PIPELINE_SECURITY_LLM` documentation setting.

### Milestone 2 — Team adoption

- Add configuration, severity thresholds, and reviewed suppression reasons.
- Expand secret detection to private keys, common token formats, `.env` files,
  credential URLs, and entropy-based candidates.
- Add JSON and SARIF reports.
- Add GitHub Actions documentation and a reusable CI workflow.

### Milestone 3 — Broader coverage

- Support JavaScript/TypeScript, Dockerfiles, GitHub Actions, YAML, Terraform,
  and Kubernetes manifests.
- Add dependency and infrastructure policy integrations where they fit the
  local-first model.
- Support approved local models and stronger redaction controls for contextual
  review.

## 12. Open Decisions

- Which rule severities should block commits by default?
- Should suppressions require a ticket/reference and expiry date?
- Which project configuration format has priority: `pyproject.toml`, YAML, or
  both?
- Should the project provide a hosted GitHub Action, or only documented CLI
  integration?
- What level of redaction is sufficient before an LLM endpoint is permitted?

