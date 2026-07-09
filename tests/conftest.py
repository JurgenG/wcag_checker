"""Shared pytest fixtures and helpers for the leak_inspector test suite."""

from __future__ import annotations

import pytest

from leak_inspector.events import RequestEvent
from leak_inspector.modules.base import TrackerModule, all_modules


def make_request(
    *,
    host: str,
    url: str,
    method: str = "GET",
    request_body: str | None = None,
    headers: dict[str, str] | None = None,
    event_id: int = 1,
    timestamp: str = "2026-05-01T12:00:00Z",
    response_status: int | None = 200,
) -> RequestEvent:
    """Build a RequestEvent with sane defaults for a tracker test."""
    return RequestEvent(
        event_id=event_id,
        timestamp=timestamp,
        type="request",
        context_id=None,
        payload={},
        method=method,
        url=url,
        host=host,
        headers=headers or {},
        request_body=request_body,
        initiator=None,
        response_status=response_status,
        response_mime=None,
        response_headers={},
    )


def module_by_id(module_id: str) -> TrackerModule:
    """Return the registered module instance with the given id, or fail loudly."""
    for module in all_modules():
        if module.module_id == module_id:
            return module
    raise AssertionError(f"module {module_id!r} not registered")


@pytest.fixture
def request_factory():
    """Expose ``make_request`` to tests as a fixture (calls it like a function)."""
    return make_request
