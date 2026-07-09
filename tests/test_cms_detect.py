"""Tests for CMS platform fingerprinting.

The detector consumes the request events captured during a session and
returns a :class:`CMSFingerprint` when the platform can be identified
from highly-specific signals (vendor headers, well-known URL paths,
platform-specific cookies). Per CLAUDE.md, only certain matches ship:
detectors must use signatures that are essentially impossible to
false-positive on a non-platform site.
"""

from __future__ import annotations

from leak_inspector.cms import CMSFingerprint, detect_cms
from leak_inspector.events import RequestEvent, TYPE_REQUEST


def _req(
    *, url: str, host: str | None = None, event_id: int = 1,
    response_headers: dict[str, str] | None = None,
    response_body: str | None = None,
) -> RequestEvent:
    """Build a minimal RequestEvent for detector tests."""
    if host is None:
        from urllib.parse import urlparse
        host = urlparse(url).hostname or ""
    return RequestEvent(
        event_id=event_id, timestamp="2026-05-30T00:00:01Z",
        type=TYPE_REQUEST, context_id=None, payload={},
        method="GET", url=url, host=host, headers={},
        request_body=None, initiator=None,
        response_status=200, response_mime="text/html",
        response_headers=response_headers or {},
        response_body=response_body,
    )


# --- baseline: no signals -------------------------------------------------


def test_no_cms_signals_returns_none() -> None:
    """A site with no platform-specific URLs/headers returns None."""
    events = [_req(url="https://example.be/some-page", event_id=1)]
    assert detect_cms(events) is None


def test_empty_events_returns_none() -> None:
    assert detect_cms([]) is None


# --- WordPress -------------------------------------------------------------


def test_wordpress_detected_via_wp_content_path() -> None:
    events = [
        _req(url="https://example.be/", event_id=1),
        _req(url="https://example.be/wp-content/themes/twentytwentyfour/style.css",
             event_id=2),
    ]
    fp = detect_cms(events)
    assert fp is not None
    assert fp.name == "WordPress"


def test_wordpress_detected_via_wp_json_api() -> None:
    events = [_req(url="https://example.be/wp-json/wp/v2/posts", event_id=1)]
    assert detect_cms(events).name == "WordPress"


def test_wordpress_detected_via_wp_includes_path() -> None:
    events = [_req(
        url="https://example.be/wp-includes/js/jquery/jquery.min.js",
        event_id=1,
    )]
    assert detect_cms(events).name == "WordPress"


def test_wordpress_version_from_meta_generator_in_body() -> None:
    body = (
        "<html><head>"
        '<meta name="generator" content="WordPress 6.5.2">'
        "</head><body></body></html>"
    )
    events = [_req(
        url="https://example.be/", response_body=body, event_id=1,
    ), _req(url="https://example.be/wp-content/themes/x/style.css", event_id=2)]
    fp = detect_cms(events)
    assert fp.name == "WordPress"
    assert fp.version == "6.5.2"


def test_non_core_asset_ver_is_not_read_as_wp_version() -> None:
    """``?ver=`` on an enqueued asset is that asset's own version, not
    WordPress's — jquery.min.js?ver=3.7.1 is jQuery 3.7.1, not WP 3.7.1.
    The site is still detected as WordPress (by path), but no version is
    inferred from the foreign asset (WPScan-informed; commit 0a4bcfb)."""
    events = [_req(
        url="https://example.be/wp-includes/js/jquery/jquery.min.js?ver=3.7.1",
        event_id=1,
    )]
    fp = detect_cms(events)
    assert fp.name == "WordPress"
    assert fp.version is None


def test_wordpress_version_from_core_asset_query_param() -> None:
    """``?ver=`` on a WP *core* asset does reflect the core version."""
    events = [_req(
        url="https://example.be/wp-includes/js/wp-embed.min.js?ver=6.5.2",
        event_id=1,
    )]
    fp = detect_cms(events)
    assert fp.name == "WordPress"
    assert fp.version == "6.5.2"


# --- Drupal ----------------------------------------------------------------


def test_drupal_detected_via_x_generator_header() -> None:
    events = [_req(
        url="https://commune.be/",
        response_headers={"x-generator": "Drupal 10 (https://www.drupal.org)"},
        event_id=1,
    )]
    fp = detect_cms(events)
    assert fp.name == "Drupal"
    assert fp.version == "10"


def test_drupal_detected_via_sites_default_files_path() -> None:
    events = [
        _req(url="https://commune.be/", event_id=1),
        _req(url="https://commune.be/sites/default/files/logo.png", event_id=2),
    ]
    assert detect_cms(events).name == "Drupal"


def test_drupal_7_detected_via_misc_drupal_js() -> None:
    """`/misc/drupal.js` is Drupal 7's signature path."""
    events = [
        _req(url="https://example.be/", event_id=1),
        _req(url="https://example.be/misc/drupal.js?v=1.2", event_id=2),
    ]
    assert detect_cms(events).name == "Drupal"


def test_drupal_version_extracted_from_x_generator() -> None:
    events = [_req(
        url="https://commune.be/",
        response_headers={"X-Generator": "Drupal 7 (https://www.drupal.org)"},
        event_id=1,
    )]
    fp = detect_cms(events)
    assert fp.version == "7"


# --- Joomla ----------------------------------------------------------------


def test_joomla_detected_via_components_path() -> None:
    events = [
        _req(url="https://example.be/", event_id=1),
        _req(url="https://example.be/components/com_content/views/article/tmpl/default.php",
             event_id=2),
    ]
    assert detect_cms(events).name == "Joomla"


def test_joomla_detected_via_media_jui() -> None:
    events = [_req(
        url="https://example.be/media/jui/css/bootstrap.min.css",
        event_id=1,
    )]
    assert detect_cms(events).name == "Joomla"


def test_joomla_version_from_meta_generator() -> None:
    body = (
        '<html><head><meta name="generator" '
        'content="Joomla! 4.4 - Open Source Content Management"></head></html>'
    )
    events = [_req(
        url="https://example.be/", response_body=body, event_id=1,
    ), _req(url="https://example.be/media/jui/css/bootstrap.min.css", event_id=2)]
    fp = detect_cms(events)
    assert fp.name == "Joomla"
    assert fp.version == "4.4"


# --- TYPO3 -----------------------------------------------------------------


def test_typo3_detected_via_typo3conf_path() -> None:
    events = [
        _req(url="https://example.be/", event_id=1),
        _req(url="https://example.be/typo3conf/ext/myext/Resources/Public/JavaScript/Main.js",
             event_id=2),
    ]
    assert detect_cms(events).name == "TYPO3"


def test_typo3_detected_via_fileadmin_path() -> None:
    events = [_req(
        url="https://example.be/fileadmin/user_upload/logo.png",
        event_id=1,
    )]
    assert detect_cms(events).name == "TYPO3"


# --- AEM (Adobe Experience Manager) ---------------------------------------


def test_aem_detected_via_etc_clientlibs_path() -> None:
    """The colruyt case — AEM signature URL paths."""
    events = [
        _req(url="https://example.be/nl", event_id=1),
        _req(url="https://example.be/etc.clientlibs/core/wcm/components/tabs/v1/tabs/clientlibs.min.css",
             event_id=2),
    ]
    fp = detect_cms(events)
    assert fp.name == "Adobe Experience Manager"


def test_aem_detected_via_content_dam_path() -> None:
    events = [_req(
        url="https://example.be/content/dam/myorg/images/banner.jpg",
        event_id=1,
    )]
    assert detect_cms(events).name == "Adobe Experience Manager"


# --- Magento / Adobe Commerce ---------------------------------------------


def test_magento_detected_via_pub_static_path() -> None:
    """M2 uses /pub/static/version<n>/ for cache-busted assets."""
    events = [_req(
        url="https://shop.example.com/pub/static/version1716822123/frontend/Magento/luma/en_US/css/styles-m.css",
        event_id=1,
    )]
    fp = detect_cms(events)
    assert fp.name == "Magento"


def test_magento_detected_via_mage_cache_cookie() -> None:
    events = [_req(
        url="https://shop.example.com/",
        response_headers={"set-cookie": "mage-cache-storage=%7B%7D; Path=/"},
        event_id=1,
    )]
    assert detect_cms(events).name == "Magento"


# --- Sitecore --------------------------------------------------------------


def test_sitecore_detected_via_sitecore_path() -> None:
    events = [_req(
        url="https://example.com/sitecore/shell/Applications/index.aspx",
        event_id=1,
    )]
    assert detect_cms(events).name == "Sitecore"


def test_sitecore_detected_via_dash_slash_media() -> None:
    events = [
        _req(url="https://example.com/", event_id=1),
        _req(url="https://example.com/-/media/images/hero.jpg", event_id=2),
    ]
    assert detect_cms(events).name == "Sitecore"


# --- Shopify ---------------------------------------------------------------


def test_shopify_detected_via_x_shopid_header() -> None:
    events = [_req(
        url="https://shop.example.com/",
        response_headers={"x-shopid": "12345678"},
        event_id=1,
    )]
    assert detect_cms(events).name == "Shopify"


def test_shopify_detected_via_myshopify_host() -> None:
    events = [_req(
        url="https://store.myshopify.com/products/widget",
        event_id=1,
    )]
    assert detect_cms(events).name == "Shopify"


def test_shopify_detected_via_cdn_shopify_com_asset() -> None:
    events = [
        _req(url="https://example.com/", event_id=1),
        _req(url="https://cdn.shopify.com/s/files/1/0/asset.js", event_id=2),
    ]
    assert detect_cms(events).name == "Shopify"


# --- Fingerprint contract --------------------------------------------------


def test_fingerprint_carries_evidence() -> None:
    """The detector explains *why* it claimed a match."""
    events = [_req(
        url="https://example.be/wp-content/themes/x/style.css",
        event_id=1,
    )]
    fp = detect_cms(events)
    assert fp.evidence  # non-empty


def test_evidence_mentions_version_source_x_generator() -> None:
    """When the version comes from a header, evidence names that source.

    The Drupal case from the field: the path triggers detection but the
    version is read off the X-Generator header on the landing page. The
    evidence string should surface that, not just the path.
    """
    events = [
        _req(
            url="https://commune.be/",
            response_headers={"x-generator": "Drupal 11 (https://www.drupal.org)"},
            event_id=1,
        ),
        _req(url="https://commune.be/sites/default/files/logo.png", event_id=2),
    ]
    fp = detect_cms(events)
    assert fp.name == "Drupal"
    assert fp.version == "11"
    assert "X-Generator header" in fp.evidence


def test_evidence_mentions_version_source_meta_generator() -> None:
    """A meta-generator-sourced version is named as such in the evidence."""
    body = (
        "<html><head>"
        '<meta name="generator" content="WordPress 6.5.2">'
        "</head><body></body></html>"
    )
    events = [
        _req(url="https://example.be/", response_body=body, event_id=1),
        _req(url="https://example.be/wp-content/themes/x/style.css", event_id=2),
    ]
    fp = detect_cms(events)
    assert fp.version == "6.5.2"
    assert "meta generator tag" in fp.evidence


def test_evidence_omits_version_source_when_no_version() -> None:
    """No version found → no dangling 'version from …' clause."""
    events = [
        _req(url="https://commune.be/", event_id=1),
        _req(url="https://commune.be/sites/default/files/logo.png", event_id=2),
    ]
    fp = detect_cms(events)
    assert fp.version is None
    assert "version from" not in fp.evidence


def test_fingerprint_is_certain_by_default() -> None:
    """V1 only ships 'certain' matches per CLAUDE.md."""
    events = [_req(
        url="https://example.be/wp-content/themes/x/style.css",
        event_id=1,
    )]
    fp = detect_cms(events)
    assert fp.confidence == "certain"


def test_fingerprint_eol_fields_default_safe() -> None:
    """Without an EOL judgment from Phase 2, is_eol stays False."""
    events = [_req(
        url="https://example.be/wp-content/themes/x/style.css",
        event_id=1,
    )]
    fp = detect_cms(events)
    assert fp.is_eol is False
    assert fp.eol_note == ""


# --- Wix --------------------------------------------------------------------


def test_wix_detected_via_parastorage_host() -> None:
    """static.parastorage.com is Wix's exclusive asset CDN — a certain signal."""
    events = [
        _req(url="https://www.voxpelt.be/", event_id=1),
        _req(
            url="https://static.parastorage.com/services/editor-elements/x.js",
            host="static.parastorage.com", event_id=2,
        ),
    ]
    fp = detect_cms(events)
    assert fp is not None
    assert fp.name == "Wix"


def test_wix_detected_via_wixstatic_media_host() -> None:
    events = [_req(
        url="https://static.wixstatic.com/media/abc~mv2.jpg",
        host="static.wixstatic.com", event_id=1,
    )]
    assert detect_cms(events).name == "Wix"


def test_wix_has_no_version() -> None:
    """Wix is a continuously-deployed SaaS; it exposes no site version."""
    events = [_req(
        url="https://siteassets.parastorage.com/pages/pages/thunderbolt",
        host="siteassets.parastorage.com", event_id=1,
    )]
    fp = detect_cms(events)
    assert fp.name == "Wix"
    assert fp.version is None


# --- Squarespace ------------------------------------------------------------


def test_squarespace_detected_via_cdn_host() -> None:
    events = [
        _req(url="https://www.example.be/", event_id=1),
        _req(
            url="https://static1.squarespace.com/static/vta/x/scripts/site-bundle.js",
            host="static1.squarespace.com", event_id=2,
        ),
    ]
    fp = detect_cms(events)
    assert fp is not None
    assert fp.name == "Squarespace"


def test_squarespace_detected_via_cdn_image_host() -> None:
    events = [_req(
        url="https://images.squarespace-cdn.com/content/v1/x/logo.png?format=1500w",
        host="images.squarespace-cdn.com", event_id=1,
    )]
    assert detect_cms(events).name == "Squarespace"


def test_squarespace_has_no_version() -> None:
    events = [_req(
        url="https://definitions.sqspcdn.com/website-component-definition/x.js",
        host="definitions.sqspcdn.com", event_id=1,
    )]
    fp = detect_cms(events)
    assert fp.name == "Squarespace"
    assert fp.version is None


# --- WordPress.com ----------------------------------------------------------


def test_wordpresscom_detected_via_hosted_subdomain() -> None:
    events = [_req(
        url="https://ganzenveerbe.wordpress.com/",
        host="ganzenveerbe.wordpress.com", event_id=1,
    )]
    assert detect_cms(events).name == "WordPress.com"


def test_wordpresscom_wins_over_generic_wordpress_on_hosted_site() -> None:
    """A *.wordpress.com host serving /wp-content/ is the hosted platform —
    it must report WordPress.com, not the generic self-hosted WordPress."""
    events = [_req(
        url="https://ganzenveerbe.wordpress.com/wp-content/uploads/2025/x.png",
        host="ganzenveerbe.wordpress.com", event_id=1,
    )]
    assert detect_cms(events).name == "WordPress.com"


def test_self_hosted_wordpress_still_generic() -> None:
    """A custom-domain site serving /wp-content/ stays generic WordPress —
    we cannot certainly call it WordPress.com from wp.com infra alone."""
    events = [_req(
        url="https://www.example.be/wp-content/themes/x/style.css",
        host="www.example.be", event_id=1,
    )]
    assert detect_cms(events).name == "WordPress"


# --- Weebly -----------------------------------------------------------------


def test_weebly_detected_via_editmysite_cdn() -> None:
    events = [
        _req(url="https://www.example.be/", event_id=1),
        _req(
            url="https://cdn2.editmysite.com/js/site/main.js?buildtime=1780513462",
            host="cdn2.editmysite.com", event_id=2,
        ),
    ]
    assert detect_cms(events).name == "Weebly"


def test_weebly_detected_via_hosted_subdomain() -> None:
    events = [_req(
        url="https://muziekacademietongeren.weebly.com/files/theme/favicon.ico",
        host="muziekacademietongeren.weebly.com", event_id=1,
    )]
    assert detect_cms(events).name == "Weebly"


# --- Webflow ----------------------------------------------------------------


def test_webflow_detected_via_website_files_cdn() -> None:
    events = [_req(
        url="https://cdn.prod.website-files.com/645b520d/css/site.min.css",
        host="cdn.prod.website-files.com", event_id=1,
    )]
    assert detect_cms(events).name == "Webflow"


def test_webflow_detected_via_uploads_host() -> None:
    events = [_req(
        url="https://uploads-ssl.webflow.com/60ab65f4/asset.json",
        host="uploads-ssl.webflow.com", event_id=1,
    )]
    assert detect_cms(events).name == "Webflow"


# --- Jimdo ------------------------------------------------------------------


def test_jimdo_detected_via_jimstatic_cdn() -> None:
    events = [_req(
        url="https://assets.jimstatic.com/ckies.js.c52961c.js",
        host="assets.jimstatic.com", event_id=1,
    )]
    assert detect_cms(events).name == "Jimdo"


def test_jimdo_has_no_version() -> None:
    events = [_req(
        url="https://fonts.jimstatic.com/css?display=swap&family=Lato",
        host="fonts.jimstatic.com", event_id=1,
    )]
    fp = detect_cms(events)
    assert fp.name == "Jimdo"
    assert fp.version is None


# --- Duda --------------------------------------------------------------------


def test_duda_detected_via_multiscreensite_cdn() -> None:
    events = [
        _req(url="https://www.example.be/", event_id=1),
        _req(
            url="https://ms-cdn.multiscreensite.com/runtime-react/4211/res/js/runtime-react.js",
            host="ms-cdn.multiscreensite.com", event_id=2,
        ),
    ]
    assert detect_cms(events).name == "Duda"


def test_duda_detected_via_eu_region_host() -> None:
    events = [_req(
        url="https://rtc.eu-multiscreensite.com/performance/metrics",
        host="rtc.eu-multiscreensite.com", event_id=1,
    )]
    assert detect_cms(events).name == "Duda"


# --- Zyro / Hostinger --------------------------------------------------------


def test_zyro_detected_via_zyrosite_cdn() -> None:
    events = [_req(
        url="https://assets.zyrosite.com/abc/logo.png",
        host="assets.zyrosite.com", event_id=1,
    )]
    fp = detect_cms(events)
    assert fp.name == "Zyro / Hostinger"
    assert fp.version is None


# --- First match wins (no ambiguous double-detection) ---------------------


def test_first_match_wins_when_multiple_signatures_present() -> None:
    """A site that proxies WordPress through a Drupal frontend (rare but
    possible) should detect deterministically. Picking the first signal
    in iteration order is acceptable; the test enforces only that
    SOMETHING is returned, not which one.
    """
    events = [
        _req(url="https://example.be/wp-content/themes/x/style.css", event_id=1),
        _req(url="https://example.be/sites/default/files/logo.png", event_id=2),
    ]
    fp = detect_cms(events)
    assert fp is not None
    assert fp.name in ("WordPress", "Drupal")
