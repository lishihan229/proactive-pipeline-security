# Proactive Pipeline Security

A local-first Git pre-commit security gate for Python and Bash projects. It examines
the *staged* version of changed files, reports likely OWASP-aligned issues, and can
optionally submit a bounded diff to an LLM for contextual review.

## Design

1. **Deterministic rules run first.** They are fast, private, and block high-signal
   problems such as hard-coded secrets, `eval`, and shell injection risks.
2. **The LLM reviewer is opt-in.** It never runs unless `PIPELINE_SECURITY_LLM=1`
   is set. Review the diff before enabling it, because source code leaves the machine.
3. **The hook reads Git's index.** The feedback matches what will be committed, not
   un-staged edits in the working tree.

## Quick start

```bash
python3 -m unittest discover -s tests -v
python3 -m pipeline_security --staged
```

Install the versioned hook configuration after installing `pre-commit`:

```bash
python3 -m pip install --user pre-commit
pre-commit install
pre-commit run --all-files
```

## Optional LLM review

The LLM integration is deliberately provider-neutral. Configure an OpenAI-compatible
chat-completions endpoint, keeping credentials out of Git:

```bash
export PIPELINE_SECURITY_LLM=1
export LLM_API_KEY='...'
export LLM_API_URL='https://your-provider.example/v1/chat/completions'
export LLM_MODEL='your-model'
```

It is best to use this for warnings and let deterministic rules enforce blocking
policy. Add redaction and an approved endpoint before enabling it on proprietary code.
