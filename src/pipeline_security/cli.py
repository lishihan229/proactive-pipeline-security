import argparse
from .git import staged_content, staged_files
from .llm import review
from .rules import scan_text


def main() -> int:
    parser = argparse.ArgumentParser(description="Scan staged Python and Bash files for security risks.")
    parser.add_argument("--staged", action="store_true", help="scan staged files (the default and hook mode)")
    parser.add_argument("--llm", action="store_true", help="perform an opt-in LLM review of redacted staged content")
    args = parser.parse_args()

    files = {path: staged_content(path) for path in staged_files()}
    findings = [(path, finding) for path, content in files.items() for finding in scan_text(path, content)]

    for path, finding in findings:
        print(f"{path}:{finding.line}: {finding.severity.upper()} {finding.rule}: {finding.message}")

    if findings:
        print(f"\nBlocked commit: {len(findings)} potential security issue(s).")
        return 1
    if args.llm:
        print("\nLLM review (advisory only):")
        print(review(files))
    print("Pipeline security: no findings in staged Python/Bash files.")
    return 0
