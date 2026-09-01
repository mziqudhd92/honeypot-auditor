"""ProbeTransportManager tests."""

from __future__ import annotations

import asyncio

from honeypot_auditor.transport import ProbeTransportManager


def test_transport_limits_concurrency():
    mgr = ProbeTransportManager(max_concurrent_sockets=2)
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
        return await asyncio.gather(*[mgr.execute_probe(slow_probe()) for _ in range(6)])

    results = asyncio.run(run_all())
    assert results == ["ok"] * 6
    assert peak <= 2
