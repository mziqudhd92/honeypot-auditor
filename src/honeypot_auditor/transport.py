"""Probe transport manager with concurrency budget."""

from __future__ import annotations

import asyncio
import random
import time
from collections.abc import Awaitable, Callable
from typing import TypeVar

from honeypot_auditor.settings import settings

T = TypeVar("T")

# Module-level singleton used by CLI orchestration
_manager: ProbeTransportManager | None = None


class ProbeTransportManager:
    """Global semaphore limiting in-flight socket probes."""

    def __init__(self, max_concurrent_sockets: int = 32) -> None:
        self._semaphore = asyncio.Semaphore(max(1, max_concurrent_sockets))
        self.max_concurrent = max(1, max_concurrent_sockets)

    async def execute_probe(
        self,
        probe_coro: Awaitable[T],
        *,
        timeout: float = 5.0,
    ) -> T:
        async with self._semaphore:
            return await asyncio.wait_for(probe_coro, timeout=timeout)

    async def run_sync(
        self,
        fn: Callable[[], T],
        *,
        timeout: float = 5.0,
        jitter: bool = True,
    ) -> T:
        if jitter:
            _apply_jitter()
        return await self.execute_probe(asyncio.to_thread(fn), timeout=timeout)


def get_transport_manager() -> ProbeTransportManager:
    global _manager
    if _manager is None or _manager.max_concurrent != settings.max_concurrent:
        _manager = ProbeTransportManager(settings.max_concurrent)
    return _manager


def _apply_jitter() -> None:
    if settings.jitter_ms_range:
        lo, hi = settings.jitter_ms_range
        delay = random.uniform(lo / 1000.0, hi / 1000.0)
    elif settings.jitter_fraction > 0:
        delay = random.uniform(0, settings.jitter_fraction * settings.timeout_seconds)
    else:
        return
    time.sleep(delay)
