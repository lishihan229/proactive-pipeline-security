"""Small, explainable static checks mapped to common OWASP failure modes."""

from dataclasses import dataclass
import re


@dataclass(frozen=True)
class Finding:
    rule: str
    severity: str
    line: int
    message: str


RULES: tuple[tuple[str, str, re.Pattern[str], str], ...] = (
    ("A02-hardcoded-secret", "high", re.compile(r"(?i)(api[_-]?key|secret|password|token)\s*=\s*['\"][^'\"]{8,}"), "Possible hard-coded credential. Use an environment variable or a secret manager."),
    ("A03-code-injection", "high", re.compile(r"\b(eval|exec)\s*\("), "Dynamic code execution can enable injection. Avoid eval/exec for untrusted data."),
    ("A03-shell-injection", "high", re.compile(r"subprocess\.(run|call|Popen)\([^\n]*shell\s*=\s*True"), "shell=True can turn input into shell commands. Prefer argument lists and shell=False."),
    ("A03-sql-injection", "high", re.compile(r"(?i)(execute|executemany)\s*\(\s*f['\"]"), "SQL f-string detected. Use parameterized queries instead."),
    ("A05-unsafe-deserialization", "high", re.compile(r"yaml\.load\s*\([^\n]*(?!Loader\s*=\s*yaml\.SafeLoader)"), "Unsafe YAML loading may execute attacker-controlled objects. Use yaml.safe_load."),
    ("A05-debug-mode", "medium", re.compile(r"(?i)debug\s*=\s*True"), "Debug mode should not be enabled in production."),
    ("A02-weak-crypto", "medium", re.compile(r"hashlib\.(md5|sha1)\s*\("), "MD5/SHA-1 are unsuitable for security-sensitive hashing."),
    ("A03-bash-command-substitution", "medium", re.compile(r"\beval\s+|`[^`]+`"), "eval or legacy backticks make shell input handling risky; use arrays and $(...) carefully."),  # pps: ignore
)


def scan_text(path: str, content: str) -> list[Finding]:
    findings: list[Finding] = []
    for number, line in enumerate(content.splitlines(), start=1):
        if "# pps: ignore" in line:
            continue
        for rule, severity, pattern, message in RULES:
            if pattern.search(line):
                findings.append(Finding(rule, severity, number, message))
    return findings
