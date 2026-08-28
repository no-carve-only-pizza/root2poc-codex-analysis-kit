"""Reject private case material and unsafe artifacts from the Git index."""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path, PurePosixPath

PROJECT_ROOT = Path(__file__).resolve().parents[2]
ALLOWED_TOP_LEVEL = {
    ".agents",
    ".codex",
    ".gitignore",
    "AGENTS.md",
    "README.md",
    "research",
}
ALLOWED_RESEARCH_PREFIXES = (
    "research/templates/",
    "research/tools/closed_source_context/",
    "research/tools/repository_preflight.py",
)
FORBIDDEN_SUFFIXES = {
    ".7z",
    ".doc",
    ".docm",
    ".dll",
    ".dmp",
    ".exe",
    ".hwp",
    ".hwpx",
    ".i64",
    ".id0",
    ".id1",
    ".idb",
    ".key",
    ".p12",
    ".pem",
    ".pfx",
    ".ppt",
    ".pptx",
    ".rtf",
    ".xls",
    ".xlsx",
    ".zip",
}
FORBIDDEN_NAME_PARTS = (
    ".env",
    "password",
    "private-key",
    "private_key",
    "session-token",
)
FORBIDDEN_TEXT = (
    re.compile("-----BEGIN " + r"[A-Z ]*PRIVATE KEY-----"),
    re.compile("/" + r"Users/[^/\s]+/"),
    re.compile(r"[A-Za-z]:\\" + r"Users\\[^\\\s]+\\"),
    re.compile("Team-" + "VM-SSH"),
)
MAX_TRACKED_FILE_BYTES = 2 * 1024 * 1024


def tracked_paths() -> list[PurePosixPath]:
    result = subprocess.run(
        ["git", "-C", str(PROJECT_ROOT), "ls-files", "-z"],
        check=False,
        capture_output=True,
    )
    if result.returncode != 0:
        raise RuntimeError("Git is not initialized or the index is unavailable")
    return [
        PurePosixPath(raw.decode("utf-8")) for raw in result.stdout.split(b"\0") if raw
    ]


def inspect_path(relative: PurePosixPath) -> list[str]:
    errors: list[str] = []
    path_text = relative.as_posix()
    top = relative.parts[0]
    if top not in ALLOWED_TOP_LEVEL:
        errors.append(f"non-core top-level path: {path_text}")
    if top == "research" and not path_text.startswith(ALLOWED_RESEARCH_PREFIXES):
        errors.append(f"private research path: {path_text}")

    lowered_name = relative.name.lower()
    if any(part in lowered_name for part in FORBIDDEN_NAME_PARTS):
        errors.append(f"sensitive filename: {path_text}")
    if relative.suffix.lower() in FORBIDDEN_SUFFIXES:
        errors.append(f"forbidden artifact type: {path_text}")

    absolute = PROJECT_ROOT / relative
    if absolute.is_symlink():
        errors.append(f"symlink is not allowed in the shared core: {path_text}")
        return errors
    if not absolute.is_file():
        errors.append(f"tracked path is not a regular file: {path_text}")
        return errors
    if absolute.stat().st_size > MAX_TRACKED_FILE_BYTES:
        errors.append(f"tracked file exceeds 2 MiB: {path_text}")
        return errors

    try:
        content = absolute.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        errors.append(f"non-text tracked file requires explicit review: {path_text}")
        return errors
    for pattern in FORBIDDEN_TEXT:
        if pattern.search(content):
            errors.append(f"sensitive or machine-specific text in: {path_text}")
    return errors


def main() -> int:
    try:
        paths = tracked_paths()
    except RuntimeError as error:
        print(f"FAIL: {error}", file=sys.stderr)
        return 2
    if not paths:
        print("FAIL: the Git index is empty", file=sys.stderr)
        return 2

    errors = [error for path in paths for error in inspect_path(path)]
    if errors:
        for error in errors:
            print(f"FAIL: {error}", file=sys.stderr)
        return 1
    print(f"PASS: {len(paths)} tracked core files passed repository preflight")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
