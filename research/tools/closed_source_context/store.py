"""Safe append-only storage for hook-visible, derived analysis state."""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import re
import tempfile
import time
from collections.abc import Iterator
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

EVENT_SCHEMA_VERSION = 1
SCHEMA_VERSION = EVENT_SCHEMA_VERSION
STATE_RELATIVE_ROOT = Path("research/.agent-state/closed-source")
MAX_CAPTURE_BYTES = 2 * 1024 * 1024

_SENSITIVE_KEY = re.compile(
    r"(?i)(?:api[_-]?key|access[_-]?token|auth(?:orization)?|bearer|cookie|"
    r"password|passwd|private[_-]?key|private-token|refresh[_-]?token|"
    r"recovery[_-]?code|secret|session[_-]?token)"
)
_SECRET_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(
            r"-----BEGIN [^-\n]*PRIVATE KEY-----.*?-----END [^-\n]*PRIVATE KEY-----",
            re.DOTALL,
        ),
        "[REDACTED_PRIVATE_KEY]",
    ),
    (
        re.compile(r"(?i)(authorization\s*[:=]\s*(?:bearer|basic)\s+)[^\s\"']+"),
        r"\1[REDACTED]",
    ),
    (
        re.compile(
            r"(?i)((?:api[_-]?key|access[_-]?token|cookie|password|passwd|"
            r"private-token|refresh[_-]?token|secret|session[_-]?token)"
            r"\s*[:=]\s*)[^\s,;\"']+"
        ),
        r"\1[REDACTED]",
    ),
    (re.compile(r"\bsk-[A-Za-z0-9_-]{10,}\b"), "[REDACTED_OPENAI_KEY]"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"), "[REDACTED_GITHUB_TOKEN]"),
    (re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), "[REDACTED_SLACK_TOKEN]"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "[REDACTED_AWS_ACCESS_KEY]"),
    (re.compile(r"\bAIza[0-9A-Za-z_-]{20,}\b"), "[REDACTED_GOOGLE_API_KEY]"),
    (
        re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
        "[REDACTED_JWT]",
    ),
)


def utc_now() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def redact_text(text: str) -> str:
    redacted = text
    for pattern, replacement in _SECRET_PATTERNS:
        redacted = pattern.sub(replacement, redacted)
    return redacted


def redact_value(value: Any, key_hint: str = "") -> Any:
    if key_hint and _SENSITIVE_KEY.search(key_hint):
        return "[REDACTED]"
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, dict):
        return {str(key): redact_value(item, str(key)) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact_value(item) for item in value]
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return redact_text(str(value))


def stable_id(*parts: Any, prefix: str = "evt") -> str:
    encoded = json.dumps(parts, ensure_ascii=False, sort_keys=True, default=str).encode(
        "utf-8"
    )
    return f"{prefix}-{hashlib.sha256(encoded).hexdigest()[:20]}"


def safe_run_id(session_id: Any) -> str:
    source = str(session_id or "unknown-session")
    slug = re.sub(r"[^A-Za-z0-9_-]+", "-", source).strip("-_") or "session"
    digest = hashlib.sha256(source.encode("utf-8", errors="replace")).hexdigest()[:12]
    return f"{slug[:48]}-{digest}"


def state_root(project_root: Path) -> Path:
    root = project_root.resolve()
    path = (root / STATE_RELATIVE_ROOT).resolve()
    if root not in path.parents:
        raise ValueError("state root escaped project root")
    return path


def run_directory(project_root: Path, session_id: Any) -> Path:
    path = state_root(project_root) / "runs" / safe_run_id(session_id)
    path.mkdir(parents=True, exist_ok=True)
    (path / "raw").mkdir(exist_ok=True)
    return path


def relative_pointer(project_root: Path, path: Path) -> str:
    return path.resolve().relative_to(project_root.resolve()).as_posix()


@contextlib.contextmanager
def file_lock(target: Path) -> Iterator[None]:
    """Use a small cross-platform advisory lock next to the target file."""

    lock_path = target.with_name(f".{target.name}.lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("a+b") as handle:
        handle.seek(0, os.SEEK_END)
        if handle.tell() == 0:
            handle.write(b"0")
            handle.flush()
        handle.seek(0)
        if os.name == "nt":
            import msvcrt

            handle.seek(0)
            msvcrt.locking(handle.fileno(), msvcrt.LK_LOCK, 1)
            try:
                yield
            finally:
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl

            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def atomic_write_bytes(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", dir=path.parent
    )
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, path)
    finally:
        with contextlib.suppress(FileNotFoundError):
            temporary_path.unlink()


def atomic_write_text(path: Path, text: str) -> None:
    atomic_write_bytes(path, text.encode("utf-8"))


def append_jsonl_unique(path: Path, event: dict[str, Any]) -> bool:
    event_id = str(event.get("event_id", ""))
    if not event_id:
        raise ValueError("event_id is required")
    path.parent.mkdir(parents=True, exist_ok=True)
    serialized = (
        json.dumps(event, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    )
    with file_lock(path):
        if path.exists():
            with path.open("r", encoding="utf-8", errors="replace") as existing:
                for line in existing:
                    if f'"event_id":"{event_id}"' in line:
                        return False
        descriptor = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        with os.fdopen(descriptor, "a", encoding="utf-8") as handle:
            handle.write(serialized)
            handle.flush()
            os.fsync(handle.fileno())
    return True


def record_event(
    project_root: Path, session_id: Any, event: dict[str, Any]
) -> tuple[Path, bool]:
    sanitized = redact_value(event)
    if not isinstance(sanitized, dict):
        raise TypeError("event must be a mapping")
    sanitized.setdefault("schema_version", SCHEMA_VERSION)
    sanitized.setdefault("timestamp_utc", utc_now())
    path = run_directory(project_root, session_id) / "checkpoint.jsonl"
    return path, append_jsonl_unique(path, sanitized)


def read_events(run_dir: Path) -> list[dict[str, Any]]:
    path = run_dir / "checkpoint.jsonl"
    if not path.exists():
        return []
    events: list[dict[str, Any]] = []
    with file_lock(path), path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            try:
                value = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(value, dict):
                events.append(value)
    return events


def write_capture(
    project_root: Path,
    session_id: Any,
    event_id: str,
    label: str,
    value: Any,
) -> dict[str, Any]:
    """Persist only the redacted value visible to the Codex hook."""

    sanitized = redact_value(value)
    full_bytes = json.dumps(
        sanitized, ensure_ascii=False, sort_keys=True, indent=2, default=str
    ).encode("utf-8")
    digest = hashlib.sha256(full_bytes).hexdigest()
    truncated = len(full_bytes) > MAX_CAPTURE_BYTES
    if truncated:
        half = MAX_CAPTURE_BYTES // 2
        stored_value: Any = {
            "capture_truncated": True,
            "original_redacted_size_bytes": len(full_bytes),
            "redacted_sha256": digest,
            "head": full_bytes[:half].decode("utf-8", errors="replace"),
            "tail": full_bytes[-half:].decode("utf-8", errors="replace"),
        }
    else:
        stored_value = sanitized
    filename = re.sub(r"[^A-Za-z0-9._-]+", "-", f"{event_id}-{label}")[:160] + ".json"
    path = run_directory(project_root, session_id) / "raw" / filename
    with file_lock(path):
        if path.exists():
            existing = json.loads(path.read_text(encoding="utf-8", errors="strict"))
            if isinstance(existing, dict) and existing.get("capture_truncated") is True:
                return {
                    "ref": relative_pointer(project_root, path),
                    "redacted_sha256": str(existing["redacted_sha256"]),
                    "redacted_size_bytes": int(
                        existing["original_redacted_size_bytes"]
                    ),
                    "stored_capture_truncated": True,
                    "capture_scope": "hook_visible_only",
                }
            existing_bytes = json.dumps(
                existing, ensure_ascii=False, sort_keys=True, indent=2, default=str
            ).encode("utf-8")
            return {
                "ref": relative_pointer(project_root, path),
                "redacted_sha256": hashlib.sha256(existing_bytes).hexdigest(),
                "redacted_size_bytes": len(existing_bytes),
                "stored_capture_truncated": False,
                "capture_scope": "hook_visible_only",
            }
        atomic_write_text(
            path,
            json.dumps(
                stored_value, ensure_ascii=False, sort_keys=True, indent=2, default=str
            )
            + "\n",
        )
    return {
        "ref": relative_pointer(project_root, path),
        "redacted_sha256": digest,
        "redacted_size_bytes": len(full_bytes),
        "stored_capture_truncated": truncated,
        "capture_scope": "hook_visible_only",
    }


def wait_for_file(path: Path, timeout_seconds: float = 0.5) -> bool:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if path.exists():
            return True
        time.sleep(0.01)
    return path.exists()
