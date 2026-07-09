"""Tests for the Zyro / Hostinger Website Builder platform module."""

from __future__ import annotations

import pytest

from leak_inspector.modules.base import CAT_TECHNICAL

from tests.conftest import make_request, module_by_id


@pytest.fixture
def m():
    return module_by_id("zyro")


def test_identity(m) -> None:
    assert m.module_id == "zyro"
    assert m.vendor.startswith("Hostinger")
    # Hostinger International is Lithuania-based — an EU controller.
    assert m.legal_jurisdiction == "LT"


@pytest.mark.parametrize("host", ["assets.zyrosite.com", "cdn.zyrosite.com"])
def test_matches_zyrosite_hosts(m, host) -> None:
    event = make_request(host=host, url=f"https://{host}/x")
    assert m.matches(event) is True


def test_does_not_match_unrelated(m) -> None:
    for host in ("example.com", "zyrosite.com.evil.com"):
        event = make_request(host=host, url=f"https://{host}/")
        assert m.matches(event) is False


def test_asset_only_security_rating_is_low(m) -> None:
    """Only fonts/images are served from zyrosite.com — no runtime JS."""
    assert m.impact_rating.security == 1.0


def test_font_params_are_technical(m) -> None:
    event = make_request(
        host="cdn.zyrosite.com",
        url="https://cdn.zyrosite.com/u1/google-fonts/font-file?family=Jost&subset=latin&display=swap",
    )
    cats = {p.key: p.category for p in m.parse(event).params}
    assert cats["family"] == CAT_TECHNICAL
    assert cats["display"] == CAT_TECHNICAL
