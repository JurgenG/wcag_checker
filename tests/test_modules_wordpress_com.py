"""Tests for the WordPress.com / Jetpack (Automattic) platform module."""

from __future__ import annotations

import pytest

from leak_inspector.modules.base import (
    CAT_BEHAVIORAL,
    CAT_CONTENT,
    CAT_TECHNICAL,
)

from tests.conftest import make_request, module_by_id


@pytest.fixture
def m():
    return module_by_id("wordpress_com")


def test_identity(m) -> None:
    assert m.module_id == "wordpress_com"
    assert m.vendor.startswith("Automattic")
    assert m.legal_jurisdiction == "US"


@pytest.mark.parametrize(
    "host",
    [
        "c0.wp.com",
        "s0.wp.com",
        "i0.wp.com",
        "fonts.wp.com",
        "pixel.wp.com",
        "stats.wp.com",
        "secure.gravatar.com",
        "public-api.wordpress.com",
        "r-login.wordpress.com",
    ],
)
def test_matches_automattic_infra_hosts(m, host) -> None:
    event = make_request(host=host, url=f"https://{host}/x")
    assert m.matches(event) is True


def test_does_not_claim_hosted_site_content(m) -> None:
    """The hosted site's own *.wordpress.com content is first-party — the
    module claims Automattic infra, not the visitor-facing site host."""
    for host in ("ganzenveerbe.wordpress.com", "example.com"):
        event = make_request(host=host, url=f"https://{host}/")
        assert m.matches(event) is False


def test_stats_pixel_fields_classified(m) -> None:
    event = make_request(
        host="pixel.wp.com",
        url=(
            "https://pixel.wp.com/g.gif?v=ext&blog=248850216&post=163"
            "&srv=www.gtsm.be&ref=https%3A%2F%2Fx%2F&fcp=526&tz=2"
        ),
    )
    cats = {p.key: p.category for p in m.parse(event).params}
    assert cats["fcp"] == CAT_BEHAVIORAL
    assert cats["ref"] == CAT_CONTENT
    assert cats["blog"] == CAT_TECHNICAL


def test_photon_image_params_are_technical(m) -> None:
    event = make_request(
        host="i0.wp.com",
        url="https://i0.wp.com/www.gtsm.be/wp-content/uploads/x.png?w=688&ssl=1",
    )
    cats = {p.key: p.category for p in m.parse(event).params}
    assert cats["w"] == CAT_TECHNICAL
    assert cats["ssl"] == CAT_TECHNICAL