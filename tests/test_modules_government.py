"""Tests for the governmental third-party modules.

Five modules cover the EU + Belgian federal + three Belgian regional
levels of government. They use the standard ``TrackerModule`` interface
but set ``module_kind = "government"`` so the report can group them
separately from commercial trackers / ad-tech.
"""

from __future__ import annotations

import pytest

from leak_inspector.modules.base import (
    GOVERNMENT_LEVELS,
    MODULE_KIND_GOVERNMENT,
    detect,
)

from tests.conftest import make_request, module_by_id


# --- gov_european_union ----------------------------------------------------


@pytest.fixture
def gov_eu():
    return module_by_id("gov_european_union")


def test_eu_identity(gov_eu) -> None:
    assert gov_eu.module_id == "gov_european_union"
    assert gov_eu.module_kind == MODULE_KIND_GOVERNMENT
    assert gov_eu.government_level == "european"
    assert gov_eu.government_level in GOVERNMENT_LEVELS
    assert gov_eu.legal_jurisdiction == "EU"


@pytest.mark.parametrize(
    "host",
    [
        "europa.eu",
        "ec.europa.eu",
        "data.europa.eu",
        "eur-lex.europa.eu",
        "consilium.europa.eu",
    ],
)
def test_eu_matches_europa_eu_family(gov_eu, host: str) -> None:
    event = make_request(host=host, url=f"https://{host}/x")
    assert gov_eu.matches(event) is True


def test_eu_does_not_match_random_eu_tld(gov_eu) -> None:
    """``.eu`` TLD is open registration — only ``.europa.eu`` is the institutional family."""
    event = make_request(host="example.eu", url="https://example.eu/")
    assert gov_eu.matches(event) is False


# --- gov_federal_belgium ---------------------------------------------------


@pytest.fixture
def gov_fed_be():
    return module_by_id("gov_federal_belgium")


def test_federal_be_identity(gov_fed_be) -> None:
    assert gov_fed_be.module_id == "gov_federal_belgium"
    assert gov_fed_be.module_kind == MODULE_KIND_GOVERNMENT
    assert gov_fed_be.government_level == "federal_be"
    assert gov_fed_be.legal_jurisdiction == "BE"


@pytest.mark.parametrize(
    "host",
    [
        # Multilingual government TLDs
        "www.belgium.be", "belgium.be",
        "www.belgie.be", "werk.belgie.be",
        "www.belgique.be", "emploi.belgique.be",
        "www.belgien.be",
        # Federal government suffix
        "economie.fgov.be", "finance.fgov.be", "fanc.fgov.be",
        "inami.fgov.be", "onss.fgov.be", "riziv.fgov.be", "statbel.fgov.be",
        # Federal subdomain-of-belgium
        "diplomatie.belgium.be", "health.belgium.be",
        "justice.belgium.be", "mobilit.belgium.be",
        "finance.belgium.be", "socialsecurity.belgium.be",
    ],
)
def test_federal_be_matches(gov_fed_be, host: str) -> None:
    event = make_request(host=host, url=f"https://{host}/x")
    assert gov_fed_be.matches(event) is True


def test_federal_be_does_not_shadow_matomo() -> None:
    """``matomo.bosa.be/matomo.php`` must still resolve to the Matomo tracker.

    BOSA is a federal IT agency, but ``.bosa.be`` is excluded from the
    federal-Belgium gov module's match set precisely so the actual
    Matomo deployment on it is classified as Matomo (analytics) rather
    than "Federal Belgian government". Both are true, but the more
    informative classification wins.
    """
    event = make_request(
        host="matomo.bosa.be", url="https://matomo.bosa.be/matomo.php?idsite=1"
    )
    found = detect(event)
    assert found is not None
    assert found.module_id == "matomo"


def test_federal_be_does_not_match_municipal_be(gov_fed_be) -> None:
    """``.be`` is open registration — not every Belgian site is federal gov."""
    event = make_request(host="www.brussels.be", url="https://www.brussels.be/")
    assert gov_fed_be.matches(event) is False


# --- gov_flanders ----------------------------------------------------------


@pytest.fixture
def gov_flanders():
    return module_by_id("gov_flanders")


def test_flanders_identity(gov_flanders) -> None:
    assert gov_flanders.module_id == "gov_flanders"
    assert gov_flanders.module_kind == MODULE_KIND_GOVERNMENT
    assert gov_flanders.government_level == "regional_vlaanderen"
    assert gov_flanders.legal_jurisdiction == "BE"


@pytest.mark.parametrize(
    "host",
    [
        "vlaanderen.be",
        "www.vlaanderen.be",
        "prod.widgets.burgerprofiel.vlaanderen.be",
        "widgets.vlaanderen.be",
        "authenticatie.vlaanderen.be",
        "contactapi.vlaanderen.be",
        "assets.vlaanderen.be",
    ],
)
def test_flanders_matches_vlaanderen_be(gov_flanders, host: str) -> None:
    event = make_request(host=host, url=f"https://{host}/api/v1/widget")
    assert gov_flanders.matches(event) is True


def test_flanders_does_not_match_random_be(gov_flanders) -> None:
    event = make_request(host="example.be", url="https://example.be/")
    assert gov_flanders.matches(event) is False


# --- gov_wallonia ----------------------------------------------------------


@pytest.fixture
def gov_wallonia():
    return module_by_id("gov_wallonia")


def test_wallonia_identity(gov_wallonia) -> None:
    assert gov_wallonia.module_id == "gov_wallonia"
    assert gov_wallonia.module_kind == MODULE_KIND_GOVERNMENT
    assert gov_wallonia.government_level == "regional_wallonie"
    assert gov_wallonia.legal_jurisdiction == "BE"


@pytest.mark.parametrize(
    "host",
    [
        "wallonie.be",
        "www.wallonie.be",
        "enwallonie.be",
        "actualites.enwallonie.be",
        "agenda.enwallonie.be",
    ],
)
def test_wallonia_matches(gov_wallonia, host: str) -> None:
    event = make_request(host=host, url=f"https://{host}/x")
    assert gov_wallonia.matches(event) is True


def test_wallonia_does_not_match_unrelated(gov_wallonia) -> None:
    event = make_request(host="walloon-bakery.example.be",
                          url="https://walloon-bakery.example.be/")
    assert gov_wallonia.matches(event) is False


# --- gov_brussels ----------------------------------------------------------


@pytest.fixture
def gov_brussels():
    return module_by_id("gov_brussels")


def test_brussels_identity(gov_brussels) -> None:
    assert gov_brussels.module_id == "gov_brussels"
    assert gov_brussels.module_kind == MODULE_KIND_GOVERNMENT
    assert gov_brussels.government_level == "regional_brussels_capital"
    assert gov_brussels.legal_jurisdiction == "BE"


@pytest.mark.parametrize(
    "host",
    [
        "be.brussels",
        "www.be.brussels",
        "parliament.brussels",
        "tax.brussels",
        "innoviris.brussels",
    ],
)
def test_brussels_matches_official_brussels_gov(gov_brussels, host: str) -> None:
    event = make_request(host=host, url=f"https://{host}/")
    assert gov_brussels.matches(event) is True


def test_brussels_does_not_match_municipalities_with_brussels_tld(gov_brussels) -> None:
    """Brussels municipalities use ``<name>.brussels`` (e.g. ``evere.brussels``)
    — they are NOT the regional government; they are first-party for the
    municipality the visitor is browsing. The module must not over-claim
    these or it'd mislabel municipal sites as regional gov."""
    event = make_request(host="evere.brussels", url="https://evere.brussels/")
    assert gov_brussels.matches(event) is False


# --- registration check ----------------------------------------------------


def test_all_five_government_modules_register() -> None:
    """The five gov modules must register and expose distinct government_level values."""
    ids = ["gov_european_union", "gov_federal_belgium",
           "gov_flanders", "gov_wallonia", "gov_brussels"]
    levels = {module_by_id(mid).government_level for mid in ids}
    assert levels == GOVERNMENT_LEVELS
    for mid in ids:
        assert module_by_id(mid).module_kind == MODULE_KIND_GOVERNMENT
