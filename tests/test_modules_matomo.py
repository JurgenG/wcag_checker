"""Tests for the Matomo module."""

from __future__ import annotations

import pytest

from leak_inspector.modules.base import (
    CAT_BEHAVIORAL,
    CAT_CONSENT,
    CAT_CONTENT,
    CAT_IDENTIFIER,
    CAT_OTHER,
    CAT_PII,
    CAT_TECHNICAL,
    IMPACT_HIGH,
    IMPACT_LOW,
    IMPACT_MEDIUM,
)

from tests.conftest import make_request, module_by_id


@pytest.fixture
def mm():
    return module_by_id("matomo")


def test_identity(mm) -> None:
    assert mm.module_id == "matomo"
    # Matomo is self-hostable: jurisdiction is per-instance, not per-module.
    # It's surfaced via a per-hit ``(deployment)`` ParamInfo instead.
    assert mm.legal_jurisdiction == ""


@pytest.mark.parametrize(
    "host", ["acme.matomo.cloud", "acme.innocraft.cloud", "acme.piwik.pro"],
)
def test_matches_hosted_variants(mm, host: str) -> None:
    event = make_request(host=host, url=f"https://{host}/matomo.php")
    assert mm.matches(event) is True


@pytest.mark.parametrize("path", ["/matomo.php", "/piwik.php", "/matomo.js", "/piwik.js"])
def test_matches_canonical_filenames_anywhere(mm, path: str) -> None:
    event = make_request(host="self-hosted.example.com", url=f"https://self-hosted.example.com{path}")
    assert mm.matches(event) is True


def test_matches_custom_path_with_idsite(mm) -> None:
    """The ``idsite`` query param is a strong fallback signal."""
    event = make_request(host="analytics.example.com", url="https://analytics.example.com/track?idsite=1")
    assert mm.matches(event) is True


def test_does_not_match_unrelated(mm) -> None:
    event = make_request(host="example.com", url="https://example.com/")
    assert mm.matches(event) is False


def test_matches_does_not_claim_container_directly(mm) -> None:
    """The MTM container is a *weak* signal: it must not confirm Matomo on its
    own at the module level — attribution happens in the analysis same-host
    pass (see test_analysis_matomo_same_host). So ``matches`` stays False."""
    event = make_request(
        host="cdn.example.net",
        url="https://cdn.example.net/js/container_oollhtB4.js",
    )
    assert mm.matches(event) is False


def test_id_is_high_impact(mm) -> None:
    event = make_request(host="acme.matomo.cloud", url="https://acme.matomo.cloud/matomo.php?_id=ABC")
    hit = mm.parse(event)
    p = next(p for p in hit.params if p.key == "_id")
    assert p.category == CAT_IDENTIFIER
    assert p.privacy_impact == IMPACT_HIGH


def test_uid_is_pii(mm) -> None:
    event = make_request(host="acme.matomo.cloud", url="https://acme.matomo.cloud/matomo.php?uid=user")
    hit = mm.parse(event)
    p = next(p for p in hit.params if p.key == "uid")
    assert p.category == CAT_PII


def test_cip_is_pii(mm) -> None:
    """``cip`` is a server-side IP override — direct PII."""
    event = make_request(host="acme.matomo.cloud", url="https://acme.matomo.cloud/matomo.php?cip=1.2.3.4")
    hit = mm.parse(event)
    p = next(p for p in hit.params if p.key == "cip")
    assert p.category == CAT_PII


@pytest.mark.parametrize("key", ["cid", "pv_id"])
def test_other_identifiers(mm, key: str) -> None:
    event = make_request(host="acme.matomo.cloud", url=f"https://acme.matomo.cloud/matomo.php?{key}=x")
    hit = mm.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_IDENTIFIER


@pytest.mark.parametrize("key", ["idsite", "idSite"])
def test_site_id_is_technical(mm, key: str) -> None:
    """The Matomo property/site ID is constant across visitors — technical."""
    event = make_request(host="acme.matomo.cloud", url=f"https://acme.matomo.cloud/matomo.php?{key}=x")
    hit = mm.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_TECHNICAL
    assert p.privacy_impact == IMPACT_LOW


@pytest.mark.parametrize("key", ["url", "urlref", "action_name", "link", "download", "search"])
def test_content(mm, key: str) -> None:
    event = make_request(host="acme.matomo.cloud", url=f"https://acme.matomo.cloud/matomo.php?{key}=x")
    hit = mm.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_CONTENT


@pytest.mark.parametrize("key", ["e_c", "e_a", "e_n", "e_v", "idgoal", "revenue"])
def test_behavioral(mm, key: str) -> None:
    event = make_request(host="acme.matomo.cloud", url=f"https://acme.matomo.cloud/matomo.php?{key}=x")
    hit = mm.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_BEHAVIORAL


def test_dimension_prefix_extracts_slot(mm) -> None:
    """``dimension7`` → CAT_BEHAVIORAL, meaning mentions slot 7."""
    event = make_request(host="acme.matomo.cloud", url="https://acme.matomo.cloud/matomo.php?dimension7=role")
    hit = mm.parse(event)
    p = next(p for p in hit.params if p.key == "dimension7")
    assert p.category == CAT_BEHAVIORAL
    assert p.privacy_impact == IMPACT_MEDIUM
    assert "7" in p.meaning


def test_legacy_custom_dimension_prefix(mm) -> None:
    event = make_request(host="acme.matomo.cloud", url="https://acme.matomo.cloud/matomo.php?customDimension3=x")
    hit = mm.parse(event)
    p = next(p for p in hit.params if p.key == "customDimension3")
    assert p.category == CAT_BEHAVIORAL
    assert "3" in p.meaning


def test_consent(mm) -> None:
    event = make_request(host="acme.matomo.cloud", url="https://acme.matomo.cloud/matomo.php?consent=1")
    hit = mm.parse(event)
    p = next(p for p in hit.params if p.key == "consent")
    assert p.category == CAT_CONSENT


def test_unknown_param(mm) -> None:
    event = make_request(host="acme.matomo.cloud", url="https://acme.matomo.cloud/matomo.php?weirdo=1")
    hit = mm.parse(event)
    p = next(p for p in hit.params if p.key == "weirdo")
    assert p.category == CAT_OTHER
    assert "Matomo" in p.meaning


# --- deployment annotation (hosted vs self-hosted) -------------------------


@pytest.mark.parametrize(
    "host", ["acme.matomo.cloud", "acme.innocraft.cloud", "acme.piwik.pro"],
)
def test_deployment_hosted_annotation(mm, host: str) -> None:
    """Hosted Matomo SaaS hits carry a Matomo Cloud deployment ParamInfo."""
    event = make_request(host=host, url=f"https://{host}/matomo.php?idsite=1")
    hit = mm.parse(event)
    p = next(p for p in hit.params if p.key == "(deployment) Matomo Cloud")
    assert "InnoCraft" in p.meaning
    # Hosted hits must NOT also claim self-hosted.
    assert not any(p.key == "(deployment) self-hosted" for p in hit.params)


def test_deployment_self_hosted_annotation(mm) -> None:
    """A /matomo.php hit on a non-hosted host gets the self-hosted ParamInfo."""
    event = make_request(host="matomo.bosa.be", url="https://matomo.bosa.be/matomo.php?idsite=1")
    hit = mm.parse(event)
    p = next(p for p in hit.params if p.key == "(deployment) self-hosted")
    assert p.privacy_impact == IMPACT_LOW
    assert "operator" in p.meaning.lower()
    # And not the cloud one.
    assert not any(p.key == "(deployment) Matomo Cloud" for p in hit.params)


# --- HeatmapSessionRecording plugin ----------------------------------------


def test_heatmap_session_recording_plugin_annotation(mm) -> None:
    """A request under /plugins/HeatmapSessionRecording/ carries a HIGH-impact plugin ParamInfo."""
    event = make_request(
        host="matomo.bosa.be",
        url=(
            "https://matomo.bosa.be/plugins/HeatmapSessionRecording/configs.php"
            "?idsite=1&trackerid=2&url=https%3A%2F%2Fexample.be%2F"
        ),
    )
    hit = mm.parse(event)
    p = next(p for p in hit.params if p.key == "(plugin) HeatmapSessionRecording")
    assert p.privacy_impact == IMPACT_HIGH
    assert p.category == CAT_BEHAVIORAL
    meaning = p.meaning.lower()
    assert "heatmap" in meaning
    assert "session" in meaning or "replay" in meaning


def test_plugin_annotation_absent_on_normal_matomo(mm) -> None:
    """A plain /matomo.php hit must NOT carry the plugin ParamInfo."""
    event = make_request(host="matomo.bosa.be", url="https://matomo.bosa.be/matomo.php?idsite=1")
    hit = mm.parse(event)
    assert not any(p.key.startswith("(plugin) ") for p in hit.params)


# --- Matomo Tag Manager container ------------------------------------------


def test_tag_manager_container_annotation(mm) -> None:
    """An MTM container load carries a ``(tag manager)`` ParamInfo."""
    event = make_request(
        host="matomo.paddle.be",
        url="https://matomo.paddle.be/js/container_oollhtB4.js",
    )
    hit = mm.parse(event)
    p = next(p for p in hit.params if p.key.startswith("(tag manager)"))
    assert "tag manager" in p.meaning.lower()


def test_tag_manager_annotation_absent_on_normal_matomo(mm) -> None:
    """A plain /matomo.php hit must NOT carry the tag-manager ParamInfo."""
    event = make_request(host="matomo.bosa.be", url="https://matomo.bosa.be/matomo.php?idsite=1")
    hit = mm.parse(event)
    assert not any(p.key.startswith("(tag manager)") for p in hit.params)


def test_trackerid_is_technical(mm) -> None:
    """The HeatmapSessionRecording ``trackerid`` is property-scoped — technical."""
    event = make_request(
        host="matomo.bosa.be",
        url="https://matomo.bosa.be/plugins/HeatmapSessionRecording/configs.php?idsite=1&trackerid=42",
    )
    hit = mm.parse(event)
    p = next(p for p in hit.params if p.key == "trackerid")
    assert p.category == CAT_TECHNICAL
    assert p.privacy_impact == IMPACT_LOW
