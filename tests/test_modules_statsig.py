"""Tests for the Statsig module — matched by API signature, not host.

Statsig rotates its endpoint domains to evade blockers, so detection is
keyed on the stable ``/v1/rgstr`` | ``/v1/initialize`` path plus the
``k=client-…`` / ``st`` / ``sv`` client-SDK query signature, which is
invariant across whatever domain Statsig is serving from today.
"""

from __future__ import annotations

import pytest

from leak_inspector.modules.base import CAT_IDENTIFIER, CAT_TECHNICAL

from tests.conftest import make_request, module_by_id


@pytest.fixture
def m():
    return module_by_id("statsig")


_SIG = "k=client-9oLcXXXX&st=javascript-client&sv=3.33.2&t=1781480868909&sid=ad34b1"


def test_identity(m) -> None:
    assert m.module_id == "statsig"
    assert m.vendor.startswith("Statsig")
    assert m.legal_jurisdiction == "US"


def test_evasion_privacy_rating(m) -> None:
    """Domain-rotation evasion puts privacy in the 4.5 band."""
    assert m.impact_rating.privacy == 4.5


@pytest.mark.parametrize(
    "host",
    [
        "featureassets.org",          # observed rotating domain
        "prodregistryv2.org",         # observed rotating domain
        "some-future-rotation.example",  # rotation-proof: host is irrelevant
    ],
)
@pytest.mark.parametrize("path", ["/v1/rgstr", "/v1/initialize"])
def test_matches_by_signature_on_any_host(m, host, path) -> None:
    event = make_request(host=host, url=f"https://{host}{path}?{_SIG}")
    assert m.matches(event) is True


def test_requires_client_key_signature(m) -> None:
    """A bare /v1/initialize without the Statsig client-SDK params is NOT claimed."""
    event = make_request(
        host="api.example.com",
        url="https://api.example.com/v1/initialize?foo=bar",
    )
    assert m.matches(event) is False


def test_does_not_match_server_key_or_wrong_path(m) -> None:
    # server key (secret-…) is never a browser request; and a non-Statsig path
    no_path = make_request(
        host="featureassets.org",
        url=f"https://featureassets.org/v2/other?{_SIG}",
    )
    assert m.matches(no_path) is False


def test_classifies_session_id_and_technical(m) -> None:
    event = make_request(
        host="prodregistryv2.org",
        url=f"https://prodregistryv2.org/v1/rgstr?{_SIG}",
    )
    cats = {p.key: p.category for p in m.parse(event).params}
    assert cats["sid"] == CAT_IDENTIFIER
    assert cats["k"] == CAT_TECHNICAL
    assert cats["sv"] == CAT_TECHNICAL
