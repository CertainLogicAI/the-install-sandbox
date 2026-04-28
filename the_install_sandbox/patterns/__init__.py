"""Prompt injection detection patterns."""

# Regex constants for prompt injection / system prompt override detection
INJECTION_PATTERNS = [
    # Direct command to ignore
    r"ignore\s+(all\s+)?previous\s+(instructions?|prompts?|context)",
    r"forget\s+(all\s+)?previous\s+(instructions?|prompts?|context)",
    # System prompt override attempts
    r"you\s+are\s+now\s+",
    r"your\s+new\s+role\s+is",
    r"act\s+as\s+if\s+you\s+are",
    r"pretend\s+to\s+be",
    r"from\s+now\s+on\s+you\s+are",
    # Jailbreak framing
    r"jailbreak",
    r"d[a|æ]n\s*mode",          # DAN mode variants
    r"developer\s*mode",
    r"sudo\s*mode",
    # Meta-level override
    r"(system|developer)\s*:\s*new\s*instruction",
    r"override\s+previous",
    # Delimiter-based attacks
    r"<\|im_start\|>",
    r"\[system\]",
    r"\[INST\]",
]

# Keywords that strongly suggest prompt injection
INJECTION_KEYWORDS = [
    "ignore previous",
    "forget everything",
    "new instructions",
    "you are now",
    "your new role",
    "act as",
    "pretend to be",
    "jailbreak",
    "developer mode",
    "sudo mode",
    "override",
]
