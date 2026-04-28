"""Code execution pattern detection."""

EXECUTION_PATTERNS = [
    # Python dynamic code
    r"\beval\s*\(",
    r"\bexec\s*\(",
    r"\bcompile\s*\(",
    r"\b__import__\s*\(",
    # Subprocess
    r"\bos\.system\s*\(",
    r"\bos\.popen\s*\(",
    r"\bsubprocess\b",
    r"\bpopen\b",
    # Shell execution
    r"\bpty\.spawn\b",
    r"\bcommands\.getoutput\b",
]

SHELL_EXECUTION_PATTERNS = [
    r"`[^`]+`",                     # Backtick execution
    r"\$\([^)]+\)",                # $(cmd) substitution
    r";\s*\w+",                    # Command chaining with semicolon
    r"\|\s*(bash|sh|zsh|python3?)", # Pipe to shell
]

DANGEROUS_BASH = [
    "rm -rf /",
    ":(){ :|:& };:",               # Fork bomb
    "chmod +s",
    "mkfs.",
    "dd if=/dev/zero",
    "> /dev/sda",
]
