"""Opt-in, OpenAI-compatible LLM review with basic credential redaction."""

import json
import os
import re
from urllib.error import URLError
from urllib.request import Request, urlopen


MAX_REVIEW_CHARS = 12_000
SECRET_ASSIGNMENT = re.compile(r"(?i)((?:api[_-]?key|secret|password|token)\s*=\s*['\"])[^'\"]+(['\"])")


def redact(text: str) -> str:
    return SECRET_ASSIGNMENT.sub(r"\1[REDACTED]\2", text)


def review(files: dict[str, str]) -> str:
    """Return an LLM review. The caller decides whether it affects commit status."""
    api_key = os.environ.get("LLM_API_KEY")
    api_url = os.environ.get("LLM_API_URL")
    model = os.environ.get("LLM_MODEL")
    if not all((api_key, api_url, model)):
        return "LLM review skipped: set LLM_API_KEY, LLM_API_URL, and LLM_MODEL."

    source = "\n\n".join(f"### {path}\n{redact(content)}" for path, content in files.items())
    prompt = (
        "Review these staged Python/Bash files for likely OWASP Top 10 risks. "
        "Return concise findings with severity, file, line when possible, exploit path, "
        "and a safe remediation. Do not repeat secrets or provide exploit payloads.\n\n"
        + source[:MAX_REVIEW_CHARS]
    )
    payload = json.dumps({
        "model": model,
        "messages": [
            {"role": "system", "content": "You are a defensive application-security reviewer."},
            {"role": "user", "content": prompt},
        ],
        "temperature": 0,
    }).encode()
    request = Request(api_url, data=payload, headers={
        "Authorization": f"Bearer {api_key}", "Content-Type": "application/json",
    }, method="POST")
    try:
        with urlopen(request, timeout=20) as response:  # nosec B310: endpoint is user-approved configuration
            data = json.loads(response.read())
    except (URLError, TimeoutError, ValueError) as error:
        return f"LLM review unavailable: {error}"
    try:
        return data["choices"][0]["message"]["content"].strip()
    except (KeyError, IndexError, TypeError, AttributeError):
        return "LLM review returned an unexpected response format."
