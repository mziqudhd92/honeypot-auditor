"""Async socket helpers."""

from __future__ import annotations

import asyncio
from contextlib import suppress


async def open_connection(
    host: str,
    port: int,
    *,
    timeout: float = 3.0,
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    return await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)


async def tcp_transact_async(
    host: str,
    port: int,
    payload: bytes = b"",
    *,
    recv_first: bool = False,
    timeout: float = 3.0,
    max_bytes: int = 65535,
) -> tuple[bytes, str]:
    try:
        reader, writer = await open_connection(host, port, timeout=timeout)
        try:
            data = b""
            if recv_first:
                data = await asyncio.wait_for(reader.read(max_bytes), timeout=timeout)
            if payload:
                writer.write(payload)
                await writer.drain()
                chunk = await asyncio.wait_for(reader.read(max_bytes), timeout=timeout)
                data += chunk
            return data, ""
        finally:
            writer.close()
            with suppress(Exception):
                await writer.wait_closed()
    except (OSError, asyncio.TimeoutError) as exc:
        return b"", str(exc)
