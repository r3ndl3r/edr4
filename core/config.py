"""TOML configuration loading."""

from __future__ import annotations

import tomllib
from pathlib import Path
from typing import Any


def load_config(path: Path) -> dict[str, Any]:
    """Load the project configuration from *path*."""
    # tomllib expects a binary file object and handles text decoding itself. It
    # is built into Python 3.11+, so this project needs no extra TOML package.
    with path.open("rb") as config_file:
        return tomllib.load(config_file)
