import argparse
from .git import staged_content, staged_files
from .rules import scan_text


def main() -> int:
    parser = argparse.ArgumentParser(description="Scan staged Python and Bash files for security risks.")
    parser.add_argument("--staged", action="store_true", help="scan staged files (the default and hook mode)")
    args = parser.parse_args()
    del args

    findings = []
    for path in staged_files():
        findings.extend((path, finding) for finding in scan_text(path, staged_content(path)))

    for path, finding in findings:
        print(f"{path}:{finding.line}: {finding.severity.upper()} {finding.rule}: {finding.message}")

    if findings:
        print(f"\nBlocked commit: {len(findings)} potential security issue(s).")
        return 1
    print("Pipeline security: no findings in staged Python/Bash files.")
    return 0
