"""Tests for the EU OpenStreetMap community tiles module."""

from __future__ import annotations

import pytest

from leak_inspector.modules.base import CAT_OTHER, detect

from tests.conftest import make_request, module_by_id


@pytest.fixture
def m():
    return module_by_id("osm_community")


def test_identity(m) -> None:
    assert m.module_id == "osm_community"
    # The sovereign EU maps option — not a foreign controller.
    assert m.legal_jurisdiction == "EU"


@pytest.mark.parametrize("host,url", [
    ("tile.osm.be", "https://tile.osm.be/osmbe-nl/16/33637/21934.png"),
    ("osm.be", "https://osm.be/"),
    ("tile.openstreetmap.fr", "https://tile.openstreetmap.fr/osmfr/16/1/1.png"),
    ("a.tile.openstreetmap.fr", "https://a.tile.openstreetmap.fr/hot/16/1/1.png"),
])
def test_matches_eu_chapter_tiles(m, host, url) -> None:
    assert m.matches(make_request(host=host, url=url)) is True


def test_disjoint_from_osmf_org_and_de(m) -> None:
    """The OSMF .org / German .de hosts stay with the openstreetmap
    module; this module must not claim them."""
    for host, url in [
        ("tile.openstreetmap.org", "https://tile.openstreetmap.org/16/1/1.png"),
        ("tile.openstreetmap.de", "https://tile.openstreetmap.de/16/1/1.png"),
    ]:
        ev = make_request(host=host, url=url)
        assert m.matches(ev) is False
        assert detect(ev).module_id == "openstreetmap"


def test_eu_chapter_routes_to_this_module(m) -> None:
    ev = make_request(host="tile.osm.be",
                      url="https://tile.osm.be/osmbe-nl/16/1/1.png")
    assert detect(ev).module_id == "osm_community"
    ev_fr = make_request(host="tile.openstreetmap.fr",
                         url="https://tile.openstreetmap.fr/osmfr/16/1/1.png")
    assert detect(ev_fr).module_id == "osm_community"


def test_params_low_impact(m) -> None:
    ev = make_request(host="tile.osm.be",
                      url="https://tile.osm.be/osmbe-nl/16/1/1.png?v=2")
    p = next(p for p in m.parse(ev).params if p.key == "v")
    assert p.category == CAT_OTHER
