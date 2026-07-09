"""Snapshot test pinning the composite score for each fixture bundle.

Any change to the scoring model — a module impact rating, a non-module
signal rating, the logistic curve parameters (p50/s), or the
deduction/aggregation logic — will move one or more of these numbers
and surface as a test diff. The right response is almost never "weaken
the assertion": it's to re-read the change against this dataset and
decide whether the new numbers are correct.

If they ARE correct, update the expected dict here and include the diff
in the commit message of the scoring change, so the audit trail shows
how each tweak rippled through real captures.

The score is the **Scoring-v2** model (``leak_inspector/report/
score_v2.py``): every fired module and non-module signal deducts its
curated impact (0–5) per dimension; each dimension's summed penalty is
mapped through a logistic S-curve to a 0–100 score (ceil-displayed, so
1 and 99 are the reachable bounds — 0 and 100 are asymptotes); the
total is the cube root (geometric mean) of the three. Pinned via the
report document (``build_report_document(...).score``), i.e. exactly
what the report prints.

Bundle inventory lives in ``tests/fixtures/bundles/README.md``; the
rubric lives in ``docs/SCORING.md`` and the ratings in each module /
``leak_inspector/signals.py``.
"""

from __future__ import annotations

import pytest

from leak_inspector import modules  # noqa: F401  (registers detectors)
from leak_inspector import signals  # noqa: F401  (registers signal ratings)
from leak_inspector.analysis.runner import analyze_bundle
from leak_inspector.report.builder import build_report_document
from leak_inspector.report.score_v2 import ScoreView

from tests.fixtures.bundles import path as bundle_path


# Expected per-bundle scores under the Scoring-v2 model (logistic
# dimensions, p50=11 / s=5, cube-root total). Tuple is
# ``(resilience, security, privacy, total)``, each 0–100.
#
# Reading the spread (cleanest → worst):
#   * brecht — Google Fonts + gov + an Azure CDN (azureedge.net) host,
#     fully Belgian host/mail/DNS → 76. (The curve caps a penalty-free
#     dimension at ~90, so even the cleaner sites land in the 80s, not the
#     high 90s; the Azure CDN module trims resilience/security here.)
#   * nbb — self-hosted (Belgian National Bank), but mail on M365 and DNS
#     on Azure: the server-sovereignty criterion takes resilience 79 → 36.
#   * kbc — Adobe Experience Cloud + AppNexus; host/DNS on Akamai IPs that
#     geolocate to the US but whose ASN is EU-registered, so physical-only
#     sovereignty penalties → 41.
#   * aalst — Meta Pixel + Google Ads + Google-hosted (US) + M365 mail:
#     trackers plus host+mail sovereignty penalties → low 20s.
#
# EU public-sector third parties (gov / para-gov, EU jurisdiction) are
# scored leniently — 0 resilience impact, trimmed privacy/security.
#   * cultuurkuur — Hotjar + YouTube + GA + Ads, 11 modules → 3.
#   * doccle-accept / -reject — 14 / 11 trackers on a full AWS + M365 stack;
#     reject additionally tracked after the visitor said no (per-vendor
#     post-reject signals) → privacy bottoms, cube root pulls the total to
#     1 (ceil of a tiny positive — never a true 0).
#
# Resilience now reflects two posture criteria added on top of the module
# spread: every fixture is IPv4-only (−0.5 ``no_ipv6``), and the
# server-sovereignty criterion deducts physical-location (−2) and
# non-EU-jurisdiction (−3) per extra-EU component (host / mail / DNS).
# NIS2 / CyberFundamentals email+DNS posture signals (2026-06): caa_missing
# (−0.5 sec) and mta_sts_missing (−0.5 sec, MX-gated) deduct where those
# controls are absent. nbb is untouched — it publishes both CAA and MTA-STS.
# spf_weak and dns_single_nameserver fire on none of the corpus (latent
# guards: every fixture has an acceptable SPF qualifier and ≥2 nameservers).
EXPECTED_SCORES: dict[str, tuple[int, int, int, int]] = {
    "aalst.zip":         (8,  36, 46, 23),  # −mta_sts (has CAA)
    "brecht.zip":        (79, 60, 84, 74),  # −caa −mta_sts
    "cultuurkuur.zip":   (3,  2,  1,  2),  # addtoany.com now classified (addtoany: −2.5 resilience, −2.5 security)
    "doccle-accept.zip": (1,  2,  1,  1),
    "doccle-reject.zip": (1,  5,  1,  1),  # −caa −mta_sts (already near floor)
    "hindustantimes.zip": (1, 1,  1,  1),  # ad-tech-saturated non-EU news site — bottoms out; the deliberately-foreign fixture
    "kbc.zip":           (41, 41, 38, 40),  # −caa −mta_sts
    "nbb.zip":           (36, 74, 77, 59),  # publishes CAA + MTA-STS → unchanged
}


@pytest.mark.parametrize("bundle_name", sorted(EXPECTED_SCORES.keys()))
def test_fixture_bundle_score(bundle_name: str) -> None:
    """Pin the composite v2 score for one fixture bundle.

    Each tuple is ``(resilience, security, privacy, total)`` on the
    0–100 scale, read from the report document — exactly what the report
    prints.
    """
    expected_res, expected_sec, expected_priv, expected_total = (
        EXPECTED_SCORES[bundle_name]
    )

    analysis = analyze_bundle(bundle_path(bundle_name))
    score = build_report_document(analysis).score
    assert isinstance(score, ScoreView), (
        f"{bundle_name}: posture data must be present for fixture bundles"
    )

    assert score.resilience.stars == expected_res, (
        f"{bundle_name}: resilience expected {expected_res}, "
        f"got {score.resilience.stars} — {score.resilience.rationale}"
    )
    assert score.security.stars == expected_sec, (
        f"{bundle_name}: security expected {expected_sec}, "
        f"got {score.security.stars} — {score.security.rationale}"
    )
    assert score.privacy.stars == expected_priv, (
        f"{bundle_name}: privacy expected {expected_priv}, "
        f"got {score.privacy.stars} — {score.privacy.rationale}"
    )
    assert score.total == expected_total, (
        f"{bundle_name}: total expected {expected_total}, "
        f"got {score.total}"
    )


def test_snapshot_covers_every_fixture_bundle() -> None:
    """Every committed fixture bundle has a pinned snapshot — no silent gaps.

    A bundle present in ``tests/fixtures/bundles/`` but missing from
    :data:`EXPECTED_SCORES` would have its score quietly drift across
    rubric changes. This test fails when a new bundle is added without
    its expected score being pinned alongside.
    """
    from pathlib import Path
    bundles_dir = Path(bundle_path("aalst.zip")).parent
    found = {p.name for p in bundles_dir.glob("*.zip")}
    pinned = set(EXPECTED_SCORES.keys())
    missing = found - pinned
    assert not missing, (
        f"fixture bundles without pinned scores: {sorted(missing)}. "
        f"Add the expected (res, sec, priv, total) tuple to EXPECTED_SCORES."
    )
