"""Utility helpers for CertainGuard."""
import hashlib
import re
import math
from pathlib import Path
from typing import Iterator


def file_sha256(path: Path) -> str:
    """Return SHA-256 hex digest of a file."""
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()


def shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    for count in (data.count(c) for c in set(data)):
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def find_high_entropy_strings(text: str, threshold: float = 4.5, min_len: int = 12) -> list[tuple[str, float]]:
    """Find high-entropy strings that might be secrets."""
    results = []
    # Look for quoted strings, assignment values, etc.
    for match in re.finditer(r'["\']([a-zA-Z0-9_\-/+=]{12,})["\']', text):
        token = match.group(1)
        ent = shannon_entropy(token)
        if ent >= threshold:
            results.append((token, ent))
    return results


def walk_files(directory: Path, patterns: tuple[str, ...] = ("*.py", "*.md", "*.sh", "*.json", "*.yaml", "*.yml", "*.js")) -> Iterator[Path]:
    """Yield files matching patterns under directory."""
    for pat in patterns:
        yield from directory.rglob(pat)


def is_text_file(path: Path, sample_size: int = 8192) -> bool:
    """Heuristic: does the file look like text?"""
    try:
        with open(path, "rb") as f:
            chunk = f.read(sample_size)
        chunk.decode("utf-8")
        return True
    except (UnicodeDecodeError, OSError):
        return False
