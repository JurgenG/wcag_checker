"""Tests for the cookie-name → tracker classifier.

Maps well-known cookie names to the tracker module that sets them, so
JS-set first-party tracking cookies can be labelled in the inventory and
(when the vendor is forwarding/cloaking) attributed for scoring. The
mapping is by documented cookie name → ``module_id`` (the stable key the
request modules also use), keeping one vocabulary.
"""

from __future__ import annotations

import pytest

from leak_inspector.analysis.cookie_classifier import classify_cookie_tracker


@pytest.mark.parametrize(
    "name, module_id",
    [
        ("_ga", "ga4"),
        ("_ga_K9DMZHMTJP", "ga4"),
        ("_gid", "ga4"),
        ("_gat_gtag_UA_31801406_1", "ga4"),
        ("_gat_UA-31801406-1", "ga4"),
        ("_fbp", "facebook_pixel"),
        ("_fbc", "facebook_pixel"),
        ("_gcl_au", "google_ads"),
        ("_clck", "clarity"),
        ("_clsk", "clarity"),
        ("_hjSessionUser_190318", "hotjar"),
        ("_hjSession_190318", "hotjar"),
        ("_pk_id.1.2129", "matomo"),
        ("_pk_ses.1.335f", "matomo"),
        ("AMCV_DB71403D53BBF4B80A490D4C%40AdobeOrg", "adobe_marketing_cloud"),
        ("AMCVS_DB71403D53BBF4B80A490D4C%40AdobeOrg", "adobe_marketing_cloud"),
    ],
)
def test_known_tracker_cookies_classify(name: str, module_id: str) -> None:
    result = classify_cookie_tracker(name)
    assert result is not None, f"{name} should classify"
    assert result[0] == module_id
    assert result[1]  # a non-empty human label


@pytest.mark.parametrize(
    "name",
    [
        "cookie-agreed",
        "cookie-agreed-categories",
        "PHPSESSID",
        "pll_language",
        "doccle_lang",
        "oswald_session_id",
        "",
        "_gafoo",          # not the GA pattern (no boundary)
        "session",
    ],
)
def test_benign_cookies_do_not_classify(name: str) -> None:
    assert classify_cookie_tracker(name) is None


def test_label_matches_known_vendor() -> None:
    assert classify_cookie_tracker("_ga")[1] == "Google Analytics"
    assert classify_cookie_tracker("_fbp")[1] == "Meta Pixel"
    assert classify_cookie_tracker("AMCV_x")[1] == "Adobe Experience Cloud"
