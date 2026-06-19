"""Org-level configuration constants."""

from __future__ import annotations

from typing import Literal

FailMode = Literal["deny_on_error", "allow_with_flag"]
Region = Literal["uae", "mena", "global"]

FAIL_MODES: frozenset[str] = frozenset({"deny_on_error", "allow_with_flag"})
REGIONS: frozenset[str] = frozenset({"uae", "mena", "global"})

DEFAULT_FAIL_MODE: FailMode = "deny_on_error"
DEFAULT_REGION: Region = "uae"
