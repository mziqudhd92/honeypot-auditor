"""Runtime settings (set once per CLI invocation)."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class Settings:
    timeout_seconds: float = 3.0
    deep: bool = False


settings = Settings()
