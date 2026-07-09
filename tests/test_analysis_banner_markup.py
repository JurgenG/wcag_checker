"""Tests for self-hosted consent-banner detection from page-source markup.

``detect_self_hosted_banners`` scans the captured page-source HTML for
server-rendered consent banners that have no third-party CMP host — the
decision lives first-party, so the hosted-CMP decoders never see them.

All positive fixtures are **real markup captured through our own
pipeline** (curl-derived signatures do not survive rendering — the
beernem lesson):

* ``www.beernem.be`` — LCP/Icordis, carrying the rendered signals
  (typo'd ``cookie-complicance-wrapper``, localized
  ``/cookieverklaring`` action, no ``cookie-compliance-form`` class).
* ``www.anderlecht.be`` — Drupal EU Cookie Compliance, asset-path
  confirmed (the ``eu_cookie_compliance`` module also fired).
* ``www.leuven.be`` — Drupal EU Cookie Compliance with the asset path
  hidden by Drupal JS aggregation: the markup fallback's target case.

The two families share class vocabulary (LCP reuses
``eu-cookie-compliance-more-button``) and must never be conflated:
LCP's load-bearing signal is the accept/decline form POST; ECC's is
the module-owned banner class in a real ``class`` attribute. The
``sjtn.brussels`` negative pins that ECC config embedded as escaped
JSON in ``Drupal.settings`` (banner never injected into the DOM) is
not claimed as a banner.
"""

from __future__ import annotations

import json
from pathlib import Path

from leak_inspector.analysis.banner_markup import (
    EU_COOKIE_COMPLIANCE_BANNER,
    LCP_ICORDIS_BANNER,
    detect_self_hosted_banners,
)
from leak_inspector.analysis.runner import analyze_bundle
from leak_inspector.bundle import (
    BUNDLE_SCHEMA_VERSION,
    Manifest,
    TOOL_NAME,
    write_bundle,
)

# Real rendered markup from a www.beernem.be capture (trimmed).
BEERNEM_BANNER = """
<div class="cookie-complicance-wrapper" id="cookie-compliance">
  <div class="maxwidth">
    <form method="post" action="/cookieverklaring?url=%2f">
      <div class="cookie-compliance-text">Deze website maakt gebruik...</div>
      <div class="cookie-compliance-actions">
        <a href="/cookieverklaring?url=%2f"
           class="btn-cookie-compliance btn-cookie-accept">Beheer mijn cookies</a>
        <button type="submit" class="btn-cookie-compliance btn-cookie-decline"
                name="action" value="decline">Alleen essentiele cookies</button>
        <button type="submit" class="btn-cookie-compliance btn-cookie-accept"
                name="action" value="acceptall">Alles aanvaarden</button>
      </div>
    </form>
  </div>
</div>
"""

# Real rendered markup from a www.anderlecht.be capture (trimmed) —
# Drupal EU Cookie Compliance, asset-path confirmed, categories variant.
ANDERLECHT_BANNER = """
<div id="sliding-popup" role="alertdialog" aria-describedby="popup-text"
     style="height: auto; width: 100%; bottom: 0px;" class="sliding-popup-bottom">
  <div aria-labelledby="popup-text" class="eu-cookie-compliance-banner
       eu-cookie-compliance-banner-info eu-cookie-compliance-banner--categories"
       aria-hidden="false">
    <div class="popup-content info eu-cookie-compliance-content">
      <div id="popup-text" class="eu-cookie-compliance-message" role="document">
        <h2>Cookies</h2><p>...</p>
      </div>
      <button type="button" class="find-more-button eu-cookie-compliance-more-button
              find-more-button-processed" tabindex="0">En savoir plus</button>
      <div id="eu-cookie-compliance-categories"
           class="eu-cookie-compliance-categories"></div>
      <button type="button" class="agree-button eu-cookie-compliance-default-button"
              tabindex="0">Accepter</button>
    </div>
  </div>
</div>
"""

# Real rendered markup from a www.leuven.be capture (trimmed) — Drupal
# EU Cookie Compliance whose asset path is hidden by JS aggregation:
# exactly the case the markup fallback exists for.
LEUVEN_BANNER = """
<div id="sliding-popup" role="alertdialog" aria-describedby="popup-text"
     aria-label="Cookie compliance banner" style="top: 0px;"
     class="sliding-popup-top clearfix">
  <div class="eu-cookie-compliance-banner" aria-hidden="false">
    <div class="container">
      <div class="popup-content info eu-cookie-compliance-banner__content">
        <div id="popup-text" class="eu-cookie-compliance-banner__message">
          <p>... <a href="/cookies" tabindex="0">cookiebeleid</a></p>
        </div>
        <button type="button" class="agree-button eu-cookie-compliance-default-button
                btn btn-primary" tabindex="0">Akkoord</button>
      </div>
    </div>
  </div>
</div>
"""

# Real negative from a sjtn.brussels capture (trimmed): the ECC banner
# template lives only as escaped JSON inside Drupal.settings — the
# banner was never injected into the DOM, so no banner may be claimed.
# (The asset-path module still names ECC on that capture.)
SJTN_SETTINGS_ONLY = """
<script>jQuery.extend(Drupal.settings, {"eu_cookie_compliance":
{"cookie_policy_version":"1.0.0","popup_enabled":1,
"popup_html_info":"\\u003Cdiv class=\\u0022eu-cookie-compliance-banner
eu-cookie-compliance-banner-info\\u0022\\u003E\\n
\\u003Cbutton class=\\u0022agree-button
eu-cookie-compliance-default-button\\u0022\\u003E"}});</script>
"""


# --- pure detector ----------------------------------------------------------


def test_detects_lcp_icordis_from_real_rendered_markup() -> None:
    assert detect_self_hosted_banners([BEERNEM_BANNER]) == [LCP_ICORDIS_BANNER]


def test_does_not_conflate_drupal_eu_cookie_compliance() -> None:
    """The families share class vocabulary; each markup names only its
    own banner."""
    assert detect_self_hosted_banners([ANDERLECHT_BANNER]) == \
        [EU_COOKIE_COMPLIANCE_BANNER]
    assert detect_self_hosted_banners([BEERNEM_BANNER]) == \
        [LCP_ICORDIS_BANNER]


def test_detects_drupal_ecc_from_asset_confirmed_markup() -> None:
    assert detect_self_hosted_banners([ANDERLECHT_BANNER]) == \
        [EU_COOKIE_COMPLIANCE_BANNER]


def test_detects_js_aggregated_drupal_ecc() -> None:
    """leuven: the asset path is hidden by Drupal JS aggregation, so
    only this markup detection can name the banner."""
    assert detect_self_hosted_banners([LEUVEN_BANNER]) == \
        [EU_COOKIE_COMPLIANCE_BANNER]


def test_settings_json_without_dom_banner_is_not_claimed() -> None:
    """sjtn: ECC config as escaped JSON in Drupal.settings, banner never
    injected — presence of the strings is not presence of a banner."""
    assert detect_self_hosted_banners([SJTN_SETTINGS_ONLY]) == []


def test_ecc_name_matches_module_name() -> None:
    """Both detection paths (asset-path module + markup) must feed the
    same name into ``consent.cmp_names`` so set-union dedup collapses
    them — the LCP invariant, applied to ECC."""
    from leak_inspector.modules.base import all_modules

    module = next(
        m for m in all_modules() if m.module_id == "eu_cookie_compliance"
    )
    assert EU_COOKIE_COMPLIANCE_BANNER == module.module_name


def test_detects_both_banners_from_a_generator() -> None:
    """``htmls`` may be a one-shot iterable; the second detector must
    still see every document."""
    got = detect_self_hosted_banners(iter([BEERNEM_BANNER, LEUVEN_BANNER]))
    assert set(got) == {LCP_ICORDIS_BANNER, EU_COOKIE_COMPLIANCE_BANNER}


def test_no_banner_in_plain_page() -> None:
    assert detect_self_hosted_banners(["<html><body>hi</body></html>"]) == []


def test_deduplicates_across_multiple_page_sources() -> None:
    got = detect_self_hosted_banners([BEERNEM_BANNER, BEERNEM_BANNER])
    assert got == [LCP_ICORDIS_BANNER]


def test_tolerates_empty_or_none_html() -> None:
    assert detect_self_hosted_banners(["", None, BEERNEM_BANNER]) == \
        [LCP_ICORDIS_BANNER]


# --- analyze_bundle integration ---------------------------------------------


def _manifest() -> Manifest:
    return Manifest.from_dict({
        "bundle_schema": BUNDLE_SCHEMA_VERSION,
        "tool": TOOL_NAME,
        "tool_version": "0.1.0",
        "session_id": "s",
        "started_at": "2026-06-08T00:00:00Z",
        "ended_at": "2026-06-08T00:01:00Z",
        "target_url": "https://www.beernem.be/",
        "base_domain": "beernem.be",
        "browser": {"name": "firefox", "version": "151"},
        "profile": "default",
        "landing_url": "https://www.beernem.be/",
    })


def _bundle_with_html(tmp_path: Path, html: str) -> Path:
    session = tmp_path / "session"
    session.mkdir()
    (session / "events.jsonl").write_text("", encoding="utf-8")
    (session / "page_source.html").write_text(html, encoding="utf-8")
    out = tmp_path / "bundle.zip"
    write_bundle(session, _manifest(), out)
    return out


def test_analyze_bundle_names_self_hosted_banner_in_cmp_names(
        tmp_path: Path) -> None:
    out = _bundle_with_html(tmp_path, f"<html>{BEERNEM_BANNER}</html>")
    consent = analyze_bundle(out).consent
    assert LCP_ICORDIS_BANNER in consent.cmp_names


def test_analyze_bundle_leaves_cmp_names_untouched_without_banner(
        tmp_path: Path) -> None:
    out = _bundle_with_html(tmp_path, "<html><body>nothing</body></html>")
    consent = analyze_bundle(out).consent
    assert LCP_ICORDIS_BANNER not in consent.cmp_names
