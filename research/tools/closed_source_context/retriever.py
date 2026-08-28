"""Explicit BM25 retrieval over promoted finding cards only."""

from __future__ import annotations

import argparse
import collections
import hashlib
import json
import math
import re
import sys
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[3]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from research.tools.closed_source_context.store import (
    atomic_write_text,
    file_lock,
    redact_text,
    state_root,
    utc_now,
)

ALLOWED_REASONS = ("primitive-promotion", "chain-review")
DEFAULT_CARDS_ROOT = Path("research/active/closed-source-rce")
MAX_CARD_BYTES = 512 * 1024
MAX_QUERY_CHARS = 4_000
TOKEN_PATTERN = re.compile(r"[A-Za-z0-9_+.-]+|[가-힣]{2,}")
EVIDENCE_PATTERN = re.compile(
    r"(?<![A-Za-z0-9_.-])((?:research/)?[A-Za-z0-9_./-]*(?:evidence|observation)/[A-Za-z0-9_./-]+)"
)


@dataclass(frozen=True)
class Card:
    path: str
    title: str
    sha256: str
    token_counts: dict[str, int]
    length: int
    evidence_pointers: tuple[str, ...]


def _inside(path: Path, parent: Path) -> bool:
    resolved = path.resolve()
    root = parent.resolve()
    return resolved == root or root in resolved.parents


def tokenize(text: str) -> list[str]:
    return [token.lower() for token in TOKEN_PATTERN.findall(text)]


def _title(text: str, fallback: str) -> str:
    for line in text.splitlines():
        if line.startswith("# "):
            return line[2:].strip()
        if line.lower().startswith("title:"):
            return line.split(":", 1)[1].strip().strip("\"'")
    return fallback


def discover_cards(project_root: Path, cards_root: Path) -> list[Path]:
    root = cards_root if cards_root.is_absolute() else project_root / cards_root
    if not _inside(root, project_root):
        raise ValueError("finding-card root must stay inside the project")
    if not root.exists():
        return []
    cards = [
        path
        for path in root.rglob("FIND-*.md")
        if path.is_file()
        and path.parent.name == "findings"
        and _inside(path, project_root)
    ]
    return sorted(cards)


def read_card(project_root: Path, path: Path) -> Card:
    if path.stat().st_size > MAX_CARD_BYTES:
        raise ValueError(f"finding card exceeds {MAX_CARD_BYTES} bytes: {path.name}")
    data = path.read_bytes()
    text = data.decode("utf-8", errors="replace")
    counts = collections.Counter(tokenize(redact_text(text)))
    pointers = tuple(
        dict.fromkeys(
            match.group(1).rstrip(".,:;)") for match in EVIDENCE_PATTERN.finditer(text)
        )
    )
    return Card(
        path=path.resolve().relative_to(project_root.resolve()).as_posix(),
        title=_title(text, path.stem),
        sha256=hashlib.sha256(data).hexdigest(),
        token_counts=dict(counts),
        length=sum(counts.values()),
        evidence_pointers=pointers[:8],
    )


def build_index(
    project_root: Path, cards_root: Path = DEFAULT_CARDS_ROOT
) -> dict[str, Any]:
    cards = [
        read_card(project_root, path)
        for path in discover_cards(project_root, cards_root)
    ]
    index = {
        "schema_version": 1,
        "generated_utc": utc_now(),
        "scope": "promoted finding cards only",
        "documents": [
            {
                "path": card.path,
                "title": card.title,
                "sha256": card.sha256,
                "token_counts": card.token_counts,
                "length": card.length,
                "evidence_pointers": list(card.evidence_pointers),
            }
            for card in cards
        ],
    }
    cache_path = state_root(project_root) / "index/bm25-cache/finding-cards.json"
    with file_lock(cache_path):
        atomic_write_text(
            cache_path,
            json.dumps(index, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        )
    return index


def bm25_search(
    index: dict[str, Any], query: str, top: int = 3
) -> list[dict[str, Any]]:
    if top < 1 or top > 3:
        raise ValueError("top must be between 1 and 3")
    if len(query) > MAX_QUERY_CHARS:
        raise ValueError(f"query exceeds {MAX_QUERY_CHARS} characters")
    documents = index.get("documents", [])
    if not isinstance(documents, list) or not documents:
        return []
    query_tokens = list(dict.fromkeys(tokenize(query)))
    if not query_tokens:
        return []

    lengths = [int(document.get("length", 0)) for document in documents]
    average_length = sum(lengths) / len(lengths) if lengths else 1.0
    document_frequency = {
        token: sum(
            1 for document in documents if token in document.get("token_counts", {})
        )
        for token in query_tokens
    }
    k1 = 1.5
    b = 0.75
    results: list[dict[str, Any]] = []
    for document in documents:
        counts = document.get("token_counts", {})
        length = max(1, int(document.get("length", 0)))
        score = 0.0
        for token in query_tokens:
            frequency = int(counts.get(token, 0))
            if frequency == 0:
                continue
            df = document_frequency[token]
            inverse_document_frequency = math.log(
                1 + (len(documents) - df + 0.5) / (df + 0.5)
            )
            denominator = frequency + k1 * (
                1 - b + b * length / max(average_length, 1.0)
            )
            score += inverse_document_frequency * frequency * (k1 + 1) / denominator
        if score > 0:
            results.append(
                {
                    "path": document.get("path", ""),
                    "title": document.get("title", ""),
                    "score": round(score, 6),
                    "evidence_pointers": document.get("evidence_pointers", []),
                }
            )
    results.sort(key=lambda item: (-item["score"], item["path"]))
    return results[:top]


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Index or search promoted finding cards only. Invocation must be tied to a promotion or chain review."
    )
    parser.add_argument("--reason", required=True, choices=ALLOWED_REASONS)
    parser.add_argument("--cards-root", default=str(DEFAULT_CARDS_ROOT))
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("index")
    search_parser = subparsers.add_parser("search")
    search_parser.add_argument("query")
    search_parser.add_argument("--top", type=int, default=3, choices=(1, 2, 3))
    return parser


def main(argv: Iterable[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    index = build_index(PROJECT_ROOT, Path(args.cards_root))
    output: dict[str, Any] = {
        "schema_version": 1,
        "reason": args.reason,
        "indexed_cards": len(index["documents"]),
    }
    if args.command == "search":
        output["results"] = bm25_search(index, args.query, args.top)
        output["claim_boundary"] = "retrieval hint only; not exploit-chain evidence"
    print(json.dumps(output, ensure_ascii=False, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
