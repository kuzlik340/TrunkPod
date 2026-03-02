# honeytokens/checker.py  (or honeytokens.py if single-file)
from __future__ import annotations

import json
from pathlib import Path


_tokens: dict[str, dict[str, str]] = {}


def load(path: str | Path) -> None:
    """Load honeytoken JSON into the module-level cache."""
    global _tokens
    with open(path) as f:
        records = json.load(f)

    _tokens = {}
    for r in records:
        _tokens.setdefault(r["username"], {})[r["password"]] = r["fake_key"]


def is_honeytoken(username: str, password: str) -> bool:
    """Return True if the credential pair is a known honeytoken."""
    return password in _tokens.get(username, {})


def get_fake_key(username: str, password: str) -> str | None:
    """Return the fake_key for a honeytoken pair, or None if not found."""
    return _tokens.get(username, {}).get(password)


def all_for_user(username: str) -> dict[str, str]:
    """Return all {password: fake_key} entries for a given username."""
    return dict(_tokens.get(username, {}))


def loaded() -> bool:
    """Check whether tokens have been loaded."""
    return bool(_tokens)
