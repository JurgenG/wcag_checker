"""Tests for the active CMS version probe.

The probe runs at *analysis* time (not capture time — bundles stay
pristine). After passive detection identifies the CMS, the probe
fetches a small set of platform-canonical version-revealing files
(e.g. ``/administrator/manifests/files/joomla.xml``,
``/CHANGELOG.txt``) to extract the version when meta-generator and
header signals were stripped.

The HTTP fetcher is injected so unit tests stay hermetic.
"""

from __future__ import annotations

import pytest

from leak_inspector.cms.probe import (
    PROBE_USER_AGENT,
    probe_url_for,
    probe_version,
)


# --- per-CMS regex extraction (synthetic bodies) ---------------------------


def test_joomla_xml_version_extracted() -> None:
    """Canonical Joomla manifest XML carries ``<version>X.Y.Z</version>``."""
    body = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<extension type="file" method="upgrade">\n'
        '  <name>files_joomla</name>\n'
        "  <author>Joomla! Project</author>\n"
        "  <version>3.10.12</version>\n"
        "  <creationDate>2023-08</creationDate>\n"
        "</extension>\n"
    )
    fetcher = lambda url: body
    assert probe_version("Joomla", "https://example.be/", fetcher=fetcher) == "3.10.12"


def test_wordpress_rss_feed_version_extracted() -> None:
    """The /feed/ RSS exposes the version via ``wordpress.org/?v=X.Y.Z``."""
    body = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<rss version="2.0">\n'
        "<channel>\n"
        "  <title>Example</title>\n"
        "  <generator>https://wordpress.org/?v=6.5.2</generator>\n"
        "</channel></rss>"
    )
    fetcher = lambda url: body
    assert probe_version(
        "WordPress", "https://example.be/", fetcher=fetcher,
    ) == "6.5.2"


def test_drupal_changelog_version_extracted() -> None:
    """``/CHANGELOG.txt`` (D7) or ``/core/CHANGELOG.txt`` (D8+) leads with the version."""
    body = (
        "Drupal 7.99, 2024-08-14\n"
        "------------------------\n"
        "- Fixed bug ...\n"
    )
    fetcher = lambda url: body
    assert probe_version("Drupal", "https://commune.be/", fetcher=fetcher) == "7.99"


def test_drupal_core_changelog_used_when_root_changelog_404s() -> None:
    """D8+ moved the changelog to ``/core/CHANGELOG.txt`` — try both."""
    bodies = {
        "https://commune.be/CHANGELOG.txt": None,           # 404
        "https://commune.be/core/CHANGELOG.txt": "Drupal 10.2.6, 2024-08-14\n",
    }
    fetcher = lambda url: bodies.get(url)
    assert probe_version("Drupal", "https://commune.be/", fetcher=fetcher) == "10.2.6"


def test_magento_version_endpoint() -> None:
    """``/magento_version`` returns plain text like ``Magento/2.4.6 (Community)``."""
    fetcher = lambda url: "Magento/2.4.6 (Community)"
    assert probe_version(
        "Magento", "https://shop.example.com/", fetcher=fetcher,
    ) == "2.4.6"


# --- failure modes ---------------------------------------------------------


def test_probe_returns_none_when_fetcher_returns_none() -> None:
    """Any fetch failure (404 / timeout / DNS) returns None — no crash."""
    fetcher = lambda url: None
    assert probe_version("Joomla", "https://example.be/", fetcher=fetcher) is None


def test_probe_returns_none_for_empty_body() -> None:
    fetcher = lambda url: ""
    assert probe_version("Joomla", "https://example.be/", fetcher=fetcher) is None


def test_probe_returns_none_when_regex_does_not_match() -> None:
    """Junk body (e.g. site's 404 HTML) doesn't fake-extract a version."""
    fetcher = lambda url: "<html><body>Not Found</body></html>"
    assert probe_version("Joomla", "https://example.be/", fetcher=fetcher) is None


def test_probe_returns_none_for_unprobeable_platform() -> None:
    """AEM / Sitecore / Shopify have no canonical probe URL — explicit None."""
    fetcher = lambda url: "anything"
    assert probe_version(
        "Adobe Experience Manager", "https://example.be/", fetcher=fetcher,
    ) is None
    assert probe_version(
        "Sitecore", "https://example.com/", fetcher=fetcher,
    ) is None
    assert probe_version(
        "Shopify", "https://shop.example.com/", fetcher=fetcher,
    ) is None


# --- URL composition -------------------------------------------------------


def test_probe_url_joins_origin_and_path() -> None:
    assert probe_url_for("Joomla", "https://example.be/")[0] == \
        "https://example.be/administrator/manifests/files/joomla.xml"


def test_probe_url_ignores_path_of_landing_url() -> None:
    """A landing URL like ``https://commune.be/nl`` still probes from the origin root."""
    url = probe_url_for("Joomla", "https://commune.be/nl/welkom")[0]
    assert url == "https://commune.be/administrator/manifests/files/joomla.xml"


def test_probe_url_for_unknown_platform_is_empty() -> None:
    assert probe_url_for("Adobe Experience Manager", "https://example.be/") == ()


# --- transparency / TOS ----------------------------------------------------


def test_user_agent_identifies_tool_and_purpose() -> None:
    """Site logs should clearly show who's probing and why."""
    assert "leak_inspector" in PROBE_USER_AGENT.lower()
    assert "probe" in PROBE_USER_AGENT.lower() or "audit" in PROBE_USER_AGENT.lower()


# --- fetcher is called for each candidate URL until one returns ----------


def test_drupal_probes_both_paths_in_order() -> None:
    """The fetcher should be called for /CHANGELOG.txt first, then /core/CHANGELOG.txt."""
    calls: list[str] = []
    def fetcher(url: str) -> str | None:
        calls.append(url)
        return None  # both fail
    probe_version("Drupal", "https://commune.be/", fetcher=fetcher)
    assert calls == [
        "https://commune.be/CHANGELOG.txt",
        "https://commune.be/core/CHANGELOG.txt",
    ]


# --- SSRF guard ------------------------------------------------------------


def _record_urlopen_calls(monkeypatch) -> list:
    """Patch the cms.probe module's opener so any attempt to open is recorded.

    Returns a list that receives the URL of every attempted open. The
    SSRF guard should reject private URLs *before* the opener runs, so
    a passing test sees an empty list.
    """
    from leak_inspector.cms import probe as cms_probe
    calls: list[str] = []

    class _RecordingOpener:
        def open(self, req, timeout=None):  # noqa: ARG002
            calls.append(req.full_url if hasattr(req, "full_url") else str(req))
            raise AssertionError("opener.open() should not be called for a guarded URL")

    monkeypatch.setattr(cms_probe, "_OPENER", _RecordingOpener())
    return calls


@pytest.mark.parametrize(
    "url",
    [
        "http://10.0.0.5:8500/CHANGELOG.txt",      # RFC1918
        "http://127.0.0.1/CHANGELOG.txt",          # loopback
        "http://169.254.169.254/CHANGELOG.txt",    # AWS metadata
        "http://[::1]/CHANGELOG.txt",              # IPv6 loopback
    ],
)
def test_default_fetcher_refuses_private_host_url(monkeypatch, url: str) -> None:
    """Private addresses in the URL are refused *before* opening any connection."""
    from leak_inspector.cms.probe import _http_get
    calls = _record_urlopen_calls(monkeypatch)
    assert _http_get(url) is None
    assert calls == []  # the opener was never invoked


@pytest.mark.parametrize(
    "url",
    [
        "file:///etc/passwd",      # urllib has a file handler — must be refused
        "gopher://example.com/",   # any non-http(s) scheme
        "data:text/plain,oops",
    ],
)
def test_default_fetcher_refuses_non_http_scheme(monkeypatch, url: str) -> None:
    from leak_inspector.cms.probe import _http_get
    calls = _record_urlopen_calls(monkeypatch)
    assert _http_get(url) is None
    assert calls == []
