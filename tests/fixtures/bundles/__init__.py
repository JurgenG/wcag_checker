"""Path helper for test-owned capture bundles.

See ``README.md`` in this directory for the bundle inventory and the
policy on adding new ones. Tests should import ``path("…")`` from
this module rather than constructing paths themselves — keeps every
consumer pointed at the test-owned fixture, not the working dataset
that may be regenerated.
"""

from __future__ import annotations

from pathlib import Path

_HERE = Path(__file__).resolve().parent


def path(name: str) -> Path:
    """Return the absolute path to a bundle in ``tests/fixtures/bundles/``.

    Raises :class:`FileNotFoundError` (via the standard ``open`` error
    later in the test) if the named bundle doesn't exist — there is
    no fallback to the original working datasets.
    """
    return _HERE / name


__all__ = ["path"]
