"""Secret and credential detection patterns."""
import re

# High-entropy secret patterns
SECRET_KEYWORDS = [
    r"api[_-]?key\s*[:=]\s*['\"`]([a-zA-Z0-9_\-]{16,})['\"`]",
    r"api[_-]?secret\s*[:=]\s*['\"`]([a-zA-Z0-9_\-]{16,})['\"`]",
    r"auth[_-]?token\s*[:=]\s*['\"`]([a-zA-Z0-9_\-]{16,})['\"`]",
    r"access[_-]?token\s*[:=]\s*['\"`]([a-zA-Z0-9_\-]{16,})['\"`]",
    r"private[_-]?key\s*[:=]\s*['\"`]([a-zA-Z0-9_\-/+]{20,})['\"`]",
    r"secret[_-]?key\s*[:=]\s*['\"`]([a-zA-Z0-9_\-]{16,})['\"`]",
    r"password\s*[:=]\s*['\"`]([^'\"`]{8,})['\"`]",
    r"passwd\s*[:=]\s*['\"`]([^'\"`]{8,})['\"`]",
    r"bearer\s+([a-zA-Z0-9_\-\.]{20,})",
    r"aws_access_key_id\s*[:=]\s*['\"`]?(AKIA[0-9A-Z]{16})['\"`]?",
    r"aws_secret_access_key\s*[:=]\s*['\"`]?([0-9a-zA-Z/+=]{40})['\"`]?",
    r"ghp_[a-zA-Z0-9]{36}",                            # GitHub personal access token
    r"github[_-]?token\s*[:=]\s*['\"`](ghp_[a-zA-Z0-9]{36})['\"`]",
    r"openai[_-]?api[_-]?key\s*[:=]\s*['\"`](sk-[a-zA-Z0-9]{48})['\"`]",
    r"sk-[a-zA-Z0-9]{48}",                             # OpenAI key pattern
    r"slack[_-]?token\s*[:=]\s*['\"`](xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*)['\"`]",
    r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}",           # Slack token
]

# Entropy threshold for unlabeled high-entropy strings
ENTROPY_THRESHOLD = 4.5
MIN_SECRET_LENGTH = 12


def shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not data:
        return 0.0
    from math import log2
    entropy = 0.0
    length = len(data)
    for count in (data.count(c) for c in set(data)):
        p = count / length
        entropy -= p * log2(p)
    return entropy
