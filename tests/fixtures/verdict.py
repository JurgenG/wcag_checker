"""Realistic ``Analysis`` fixtures for the verdict-layer tests.

Two of the four shapes the verdict layer cares about come from real
bundles on disk:

* ``analysis_no_personal_data()`` → Brecht (gov_flanders widget +
  Google Fonts only; no third-party PII or identifier fields).
* ``analysis_with_personal_data()`` → cultuurkuur (Google Analytics,
  Hotjar, Meta Pixel, etc.; dozens of third-party PII fields).

Bundles are read via ``BundleReader.events()`` and passed through
``analyze_events`` (the hermetic path, no DNS / transport / CMS
network calls). Results are cached at module level so a hundred tests
don't re-parse the same zip a hundred times.

The other two shapes have no useful real-world equivalent and stay
synthetic:

* ``analysis_empty()`` — a capture that reached the page but loaded
  nothing third-party.
* ``analysis_first_party_only()`` — a hit on the captured site's own
  host, with PII params, to verify the first-party exclusion rule.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

import pytest

from leak_inspector.analysis import analyze_events
from leak_inspector.analysis.runner import Analysis
from leak_inspector.bundle.manifest import Manifest
from leak_inspector.bundle.reader import BundleReader
from leak_inspector.modules.base import (
    CAT_BEHAVIORAL,
    CAT_PII,
    Hit,
    IMPACT_HIGH,
    IMPACT_LOW,
    ParamInfo,
)


from tests.fixtures.bundles import path as bundle_path

_BRECHT = bundle_path("brecht.zip")
_CULTUURKUUR = bundle_path("cultuurkuur.zip")


# --- Real-bundle loaders ---------------------------------------------------


@lru_cache(maxsize=2)
def _load_bundle(path: Path) -> Analysis:
    """Read a bundle from disk and run the hermetic analysis pipeline.

    Cached: each bundle is parsed at most once per test session. Network-
    backed enrichments (DNS, transport, CMS probe) are NOT applied —
    those belong to ``analyze_bundle``, which we deliberately avoid here.
    """
    if not path.is_file():
        pytest.skip(f"required bundle not present: {path}")
    with BundleReader(path) as bundle:
        return analyze_events(
            bundle.manifest,
            bundle.events(),
            cname_chains=bundle.cname_chains,
        )


def analysis_no_personal_data() -> Analysis:
    """Real Brecht capture — gov widget + Google Fonts, no PII outflow."""
    return _load_bundle(_BRECHT)


def analysis_with_personal_data() -> Analysis:
    """Real cultuurkuur capture — Google Analytics, Hotjar, Meta Pixel,
    Google Ads/DoubleClick, Google Tag Manager, Google Maps."""
    return _load_bundle(_CULTUURKUUR)


# --- Synthetic edge cases (no real equivalent) ----------------------------


def _manifest(
    *,
    target: str = "https://example.be/",
    base_domain: str = "example.be",
) -> Manifest:
    return Manifest(
        bundle_schema=1, tool="leak_inspector", tool_version="0.1.0",
        session_id="s", started_at="2026-05-30T00:00:00Z",
        ended_at="2026-05-30T00:01:00Z",
        target_url=target, base_domain=base_domain,
        browser={}, profile="p", landing_url=target,
    )


def analysis_empty() -> Analysis:
    """Capture that loaded but called nothing third-party."""
    return Analysis(
        manifest=_manifest(),
        hits=[],
        untracked_requests=[],
        visited_pages=["https://example.be/"],
    )


def analysis_first_party_only() -> Analysis:
    """First-party hit with PII params — must NOT count as a third-party
    leak. The verdict line is about citizen data leaving to third
    parties; first-party data is the site's own business."""
    hit = Hit(
        module_id="first_party_form",
        module_name="First Party Form",
        url="https://example.be/contact",
        host="example.be",  # same as base_domain → first-party
        method="POST",
        response_status=200,
        started_at="2026-05-30T00:00:01Z",
        params=[ParamInfo(
            key="email", value="x", category=CAT_PII, meaning="",
            privacy_impact=IMPACT_HIGH, event_index=1,
        )],
        events=[1],
    )
    return Analysis(
        manifest=_manifest(),
        hits=[hit],
        untracked_requests=[],
        visited_pages=["https://example.be/"],
    )


# --- Small builders kept for fixtures that need a custom shape ------------


def make_param(
    *,
    key: str = "k",
    value: str = "v",
    category: str = CAT_BEHAVIORAL,
    meaning: str = "",
    privacy_impact: str = IMPACT_LOW,
    event_index: int = 1,
) -> ParamInfo:
    return ParamInfo(
        key=key, value=value, category=category, meaning=meaning,
        privacy_impact=privacy_impact, event_index=event_index,
    )


def make_hit(
    *,
    module_id: str,
    module_name: str,
    host: str,
    params: list[ParamInfo] | None = None,
    url: str = "",
    event_id: int = 1,
) -> Hit:
    return Hit(
        module_id=module_id, module_name=module_name,
        url=url or f"https://{host}/",
        host=host, method="GET", response_status=200,
        started_at="2026-05-30T00:00:01Z",
        params=params or [],
        events=[event_id],
    )


def analysis_with_hits(
    *,
    hits: list[Hit],
    target: str = "https://example.be/",
    base_domain: str = "example.be",
) -> Analysis:
    """Custom-shape Analysis for tests that need a specific module/host mix
    that isn't represented in any real bundle (e.g. mixing gov_flanders +
    google_fonts to exercise the classifier's expected/actionable counting)."""
    return Analysis(
        manifest=_manifest(target=target, base_domain=base_domain),
        hits=hits,
        untracked_requests=[],
        visited_pages=[target],
    )
