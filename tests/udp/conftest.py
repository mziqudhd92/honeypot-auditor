"""Pytest fixtures for UDP probe unit tests."""

from __future__ import annotations

import pytest

from tests.udp.harness import MockUDPTransceiver, ScriptedReply

__all__ = ["MockUDPTransceiver", "ScriptedReply", "mock_udp_cls"]


@pytest.fixture
def mock_udp_cls() -> type[MockUDPTransceiver]:
    """Expose ``MockUDPTransceiver`` to tests without importing conftest."""
    return MockUDPTransceiver
