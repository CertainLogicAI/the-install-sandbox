"""Known-good skill for testing."""

import json
import re
from pathlib import Path


def process_data(data: dict) -> str:
    """Safely process a dictionary and return a formatted string."""
    if not isinstance(data, dict):
        raise ValueError("Input must be a dictionary")
    return json.dumps(data, indent=2)


def load_config(path: Path) -> dict:
    """Load a JSON config file."""
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


CONFIG_DEFAULTS = {
    "timeout": 30,
    "retries": 3,
    "log_level": "INFO",
}
