"""Smoke test: the package imports and exposes a version string."""

import leak_inspector


def test_package_imports() -> None:
    assert leak_inspector.__version__
