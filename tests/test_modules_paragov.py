"""Tests for para-governmental (publicly-funded but not formally government) modules.

These are non-profits / intercommunal associations / sector-specific
service organisations operating on behalf of the public sector. Each
one is a distinct legal entity (publiq vzw, IMIO, …), so each gets its
own module with the entity as ``vendor``.
"""

from __future__ import annotations

import pytest

from leak_inspector.modules.base import (
    MODULE_KIND_PARA_GOVERNMENT,
    detect,
)

from tests.conftest import make_request, module_by_id


# --- paragov_imio ----------------------------------------------------------


@pytest.fixture
def imio():
    return module_by_id("paragov_imio")


def test_imio_identity(imio) -> None:
    assert imio.module_id == "paragov_imio"
    assert imio.module_kind == MODULE_KIND_PARA_GOVERNMENT
    assert imio.legal_jurisdiction == "BE"
    assert "IMIO" in imio.vendor


@pytest.mark.parametrize(
    "host",
    [
        "imio.be",
        "www.imio.be",
        "cms.imio.be",
        "chatbotproxy.imio.be",
    ],
)
def test_imio_matches_imio_be(imio, host: str) -> None:
    event = make_request(host=host, url=f"https://{host}/")
    assert imio.matches(event) is True


def test_imio_does_not_shadow_plausible_on_subdomain() -> None:
    """plausible.imio.be/js/script.js is more informatively classified as Plausible.

    The IMIO module would in principle match ``plausible.imio.be`` (it's
    under imio.be), but Plausible's own module is registered earlier and
    catches it via the ``plausible.<host>`` self-hosting convention.
    First-match-wins keeps the tracker classification.
    """
    event = make_request(host="plausible.imio.be",
                          url="https://plausible.imio.be/js/script.js")
    found = detect(event)
    assert found is not None
    assert found.module_id == "plausible"


def test_imio_does_not_match_unrelated(imio) -> None:
    event = make_request(host="example.be", url="https://example.be/")
    assert imio.matches(event) is False


# --- paragov_publiq --------------------------------------------------------


@pytest.fixture
def publiq():
    return module_by_id("paragov_publiq")


def test_publiq_identity(publiq) -> None:
    assert publiq.module_id == "paragov_publiq"
    assert publiq.module_kind == MODULE_KIND_PARA_GOVERNMENT
    assert publiq.legal_jurisdiction == "BE"
    assert "publiq" in publiq.vendor.lower()


@pytest.mark.parametrize(
    "host",
    [
        # publiq corporate
        "publiq.be", "www.publiq.be",
        # events database (the API + asset family)
        "uitdatabank.be",
        "images.uitdatabank.be",
        "projectaanvraag-api.uitdatabank.be",
        "sneeuwploeg.uitdatabank.be",
        # consumer-facing portal
        "uitinvlaanderen.be", "www.uitinvlaanderen.be",
        # SSO for cultural participation
        "uitid.be", "www.uitid.be",
        # loyalty / discount card
        "uitpas.be", "www.uitpas.be",
    ],
)
def test_publiq_matches_product_family(publiq, host: str) -> None:
    event = make_request(host=host, url=f"https://{host}/api/v1/x")
    assert publiq.matches(event) is True


def test_publiq_does_not_match_random_uit(publiq) -> None:
    """The ``uit*`` namespace is not exclusive — only the listed publiq products are claimed."""
    event = make_request(host="uitgeverij.example.be",
                          url="https://uitgeverij.example.be/")
    assert publiq.matches(event) is False


# --- paragov_smals (federal social-security IT non-profit) ----------------


@pytest.fixture
def smals():
    return module_by_id("paragov_smals")


def test_smals_identity(smals) -> None:
    assert smals.module_id == "paragov_smals"
    assert smals.module_kind == MODULE_KIND_PARA_GOVERNMENT
    assert smals.legal_jurisdiction == "BE"
    assert "Smals" in smals.vendor


@pytest.mark.parametrize(
    "host",
    [
        "smals.be",
        "www.smals.be",
        "research.smals.be",
    ],
)
def test_smals_matches(smals, host: str) -> None:
    event = make_request(host=host, url=f"https://{host}/")
    assert smals.matches(event) is True


def test_smals_does_not_match_unrelated(smals) -> None:
    event = make_request(host="smalshop.example.be", url="https://smalshop.example.be/")
    assert smals.matches(event) is False


# --- paragov_cultuurconnect (Flemish library / cultural infrastructure) ---


@pytest.fixture
def cultuurconnect():
    return module_by_id("paragov_cultuurconnect")


def test_cultuurconnect_identity(cultuurconnect) -> None:
    assert cultuurconnect.module_id == "paragov_cultuurconnect"
    assert cultuurconnect.module_kind == MODULE_KIND_PARA_GOVERNMENT
    assert cultuurconnect.legal_jurisdiction == "BE"
    assert "Cultuurconnect" in cultuurconnect.vendor


@pytest.mark.parametrize(
    "host",
    [
        "cultuurconnect.be",
        "www.cultuurconnect.be",
        "api.cultuurconnect.be",
    ],
)
def test_cultuurconnect_matches(cultuurconnect, host: str) -> None:
    event = make_request(host=host, url=f"https://{host}/")
    assert cultuurconnect.matches(event) is True


# --- paragov_vvsg (Flemish municipal association) -------------------------


@pytest.fixture
def vvsg():
    return module_by_id("paragov_vvsg")


def test_vvsg_identity(vvsg) -> None:
    assert vvsg.module_id == "paragov_vvsg"
    assert vvsg.module_kind == MODULE_KIND_PARA_GOVERNMENT
    assert vvsg.legal_jurisdiction == "BE"
    assert "VVSG" in vvsg.vendor


@pytest.mark.parametrize(
    "host",
    [
        "vvsg.be",
        "www.vvsg.be",
        "ledenservice.vvsg.be",
    ],
)
def test_vvsg_matches(vvsg, host: str) -> None:
    event = make_request(host=host, url=f"https://{host}/")
    assert vvsg.matches(event) is True


# --- paragov_uvcw (Walloon municipal association) -------------------------


@pytest.fixture
def uvcw():
    return module_by_id("paragov_uvcw")


def test_uvcw_identity(uvcw) -> None:
    assert uvcw.module_id == "paragov_uvcw"
    assert uvcw.module_kind == MODULE_KIND_PARA_GOVERNMENT
    assert uvcw.legal_jurisdiction == "BE"
    assert "UVCW" in uvcw.vendor or "Union" in uvcw.vendor


@pytest.mark.parametrize(
    "host",
    [
        "uvcw.be",
        "www.uvcw.be",
    ],
)
def test_uvcw_matches(uvcw, host: str) -> None:
    event = make_request(host=host, url=f"https://{host}/")
    assert uvcw.matches(event) is True


# --- paragov_belnet (federal research/education network) ------------------


@pytest.fixture
def belnet():
    return module_by_id("paragov_belnet")


def test_belnet_identity(belnet) -> None:
    assert belnet.module_id == "paragov_belnet"
    assert belnet.module_kind == MODULE_KIND_PARA_GOVERNMENT
    assert belnet.legal_jurisdiction == "BE"
    assert "Belnet" in belnet.vendor


@pytest.mark.parametrize(
    "host",
    [
        "belnet.be",
        "www.belnet.be",
        "noc.belnet.be",
    ],
)
def test_belnet_matches(belnet, host: str) -> None:
    event = make_request(host=host, url=f"https://{host}/")
    assert belnet.matches(event) is True


# --- registration check ----------------------------------------------------


def test_all_paragov_modules_register() -> None:
    expected = {
        "paragov_imio", "paragov_publiq",
        "paragov_smals", "paragov_cultuurconnect",
        "paragov_vvsg", "paragov_uvcw", "paragov_belnet",
    }
    for mid in expected:
        m = module_by_id(mid)
        assert m.module_kind == MODULE_KIND_PARA_GOVERNMENT
