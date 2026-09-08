"""ProbeTransportManager tests."""

from __future__ import annotations

import asyncio

from honeypot_auditor.transport import (
    ProbeTransportManager,
    get_transport_manager,
    reset_transport_manager,
)


def test_transport_limits_concurrency():
    started = 0
    peak = 0
    lock = asyncio.Lock()

    async def slow_probe():
        nonlocal started, peak
        async with lock:
            started += 1
            peak = max(peak, started)
        await asyncio.sleep(0.05)
        async with lock:
            started -= 1
        return "ok"

    async def run_all():
        mgr = ProbeTransportManager(max_concurrent_sockets=2)
        return await asyncio.gather(*[mgr.execute_probe(slow_probe()) for _ in range(6)])

    results = asyncio.run(run_all())
    assert results == ["ok"] * 6
    assert peak <= 2


def test_get_transport_manager_rebinds_across_asyncio_run():
    """Each asyncio.run() gets a fresh semaphore bound to that loop."""
    reset_transport_manager()
    seen: list[int] = []

    async def capture():
        mgr = get_transport_manager()
        seen.append(id(mgr))
        assert await mgr.run_sync(lambda: 7, jitter=False) == 7

    asyncio.run(capture())
    asyncio.run(capture())
    assert len(seen) == 2
    assert seen[0] != seen[1]
