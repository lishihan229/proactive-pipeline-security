"""Read staged content without touching un-staged working-tree changes."""

import subprocess


def staged_files() -> list[str]:
    result = subprocess.run(
        ["git", "diff", "--cached", "--name-only", "--diff-filter=ACMR"],
        check=True, text=True, capture_output=True,
    )
    return [line for line in result.stdout.splitlines() if line.endswith((".py", ".sh", ".bash"))]


def staged_content(path: str) -> str:
    result = subprocess.run(["git", "show", f":{path}"], check=True, text=True, capture_output=True)
    return result.stdout
