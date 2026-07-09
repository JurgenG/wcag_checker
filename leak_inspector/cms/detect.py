"""Pure CMS / platform detector over the captured request stream.

The :func:`detect_cms` entry point walks a list of :class:`RequestEvent`
and returns the first platform whose signature matches. Each detector
contributes:

* a list of **URL-path substrings** — matched against the request URL
  (case-sensitive; platform paths are stable in casing),
* a list of **host substrings** — for hosted platforms whose CDN host
  is the giveaway (Shopify ``cdn.shopify.com`` etc.),
* a list of **response-header signals** — header name + required prefix
  on the value, or simple presence,
* a list of **cookie-name signals** — case-insensitive match against
  ``set-cookie`` directive names,
* an optional **version extractor** — pulls a version string from a
  hit when possible.

Detectors are intentionally narrow: per CLAUDE.md we only ship
unambiguous signals. A site that loads jQuery from a generic CDN is
not a WordPress site; ``/wp-content/`` is.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, Iterable

from ..events import RequestEvent


# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------


@dataclass
class CMSFingerprint:
    """Detected platform + best-effort version.

    ``name`` is the human-readable platform label ("WordPress",
    "Adobe Experience Manager", …). ``version`` carries whatever the
    platform exposes — sometimes a full ``X.Y.Z``, sometimes just a
    major number, sometimes ``None``.

    ``confidence`` is always ``"certain"`` in v1: only signatures that
    are essentially impossible to false-positive ship. The field is
    present so a future "probable" tier can be added without breaking
    consumers.

    ``is_eol`` / ``eol_note`` are populated by the EOL judgment pass
    (Phase 2); the detector itself leaves them at safe defaults.
    """

    name: str
    version: str | None
    confidence: str
    evidence: str
    is_eol: bool = False
    eol_note: str = ""


# ---------------------------------------------------------------------------
# Detector specification
# ---------------------------------------------------------------------------


@dataclass
class _Signature:
    """One platform's matching rules. All fields are optional; any match wins."""

    name: str
    url_paths: tuple[str, ...] = ()         # substring match in the URL path
    host_suffixes: tuple[str, ...] = ()     # endswith match on the host
    header_names: tuple[str, ...] = ()      # response header presence (any value)
    header_prefixes: tuple[tuple[str, str], ...] = ()
    # ^ (header_name_lower, value_prefix_lower) — header value must start with prefix
    cookie_prefixes: tuple[str, ...] = ()   # ``set-cookie`` directive name starts-with
    version_extractor: Callable[[RequestEvent], tuple[str, str] | None] | None = None
    # ^ returns (version, source_label) so evidence can name the version source


# --- version extractors ----------------------------------------------------


_META_GENERATOR_RE = re.compile(
    r'<meta\s+[^>]*name=["\']generator["\'][^>]*content=["\']([^"\']+)["\']',
    re.IGNORECASE,
)


def _meta_generator(event: RequestEvent) -> str | None:
    """Return the ``content`` of any ``<meta name="generator">`` tag in the body."""
    body = event.response_body or ""
    if not body:
        return None
    m = _META_GENERATOR_RE.search(body)
    return m.group(1) if m else None


_WP_GENERATOR_RE = re.compile(r"^WordPress\s+([\d.]+)", re.IGNORECASE)
_WP_ASSET_VER_RE = re.compile(r"[?&]ver=([\d.]+)")
_WP_CORE_ASSETS = (
    "/wp-includes/js/wp-embed.min.js",
    "/wp-includes/js/wp-emoji-release.min.js",
)

def _wp_version(event: RequestEvent) -> tuple[str, str] | None:
    gen = _meta_generator(event)
    if gen:
        m = _WP_GENERATOR_RE.match(gen)
        if m:
            return m.group(1), "meta generator tag"
    if any(asset in event.url for asset in _WP_CORE_ASSETS):
        m = _WP_ASSET_VER_RE.search(event.url)
        if m:
            return m.group(1), "core asset ?ver= query"
    return None

_DRUPAL_GENERATOR_RE = re.compile(r"^Drupal\s+(\d+)", re.IGNORECASE)

def _drupal_version(event: RequestEvent) -> tuple[str, str] | None:
    headers = {k.lower(): v for k, v in (event.response_headers or {}).items()}
    m = _DRUPAL_GENERATOR_RE.match(headers.get("x-generator", ""))
    if m:
        return m.group(1), "X-Generator header"
    gen = _meta_generator(event)            # Drupal 7's default signal
    if gen:
        m = _DRUPAL_GENERATOR_RE.match(gen)
        if m:
            return m.group(1), "meta generator tag"
    return None


_JOOMLA_GENERATOR_RE = re.compile(r"^Joomla!?\s+([\d.]+)", re.IGNORECASE)


def _joomla_version(event: RequestEvent) -> tuple[str, str] | None:
    gen = _meta_generator(event)
    if not gen:
        return None
    m = _JOOMLA_GENERATOR_RE.match(gen)
    return (m.group(1), "meta generator tag") if m else None


_TYPO3_GENERATOR_RE = re.compile(r"^TYPO3\s+CMS\s+([\d.]+)", re.IGNORECASE)


def _typo3_version(event: RequestEvent) -> tuple[str, str] | None:
    gen = _meta_generator(event)
    if not gen:
        return None
    m = _TYPO3_GENERATOR_RE.match(gen)
    return (m.group(1), "meta generator tag") if m else None


# ---------------------------------------------------------------------------
# Platform signatures
# ---------------------------------------------------------------------------


_SIGNATURES: tuple[_Signature, ...] = (
    _Signature(
        name="WordPress.com",
        # Automattic's hosted platform serves the site itself from a
        # ``*.wordpress.com`` host. Ordered before generic WordPress so a
        # hosted site (which also serves ``/wp-content/``) reports the
        # platform, not the self-hosted CMS. ``*.wp.com`` is deliberately
        # NOT a signal here: it is shared with Jetpack on self-hosted
        # WordPress, so it cannot certainly mean WordPress.com hosting.
        url_paths=(),
        host_suffixes=(".wordpress.com",),
    ),
    _Signature(
        name="WordPress",
        url_paths=("/wp-content/", "/wp-includes/", "/wp-json/",
                   "/xmlrpc.php", "/wp-login.php"),
        version_extractor=_wp_version,
    ),
    _Signature(
        name="Drupal",
        url_paths=("/sites/default/files/", "/sites/all/modules/",
                   "/sites/all/themes/", "/core/themes/",
                   "/core/modules/", "/misc/drupal.js"),
        header_prefixes=(("x-generator", "drupal"),),
        version_extractor=_drupal_version,
    ),
    _Signature(
        name="Joomla",
        url_paths=("/media/jui/", "/components/com_",
                   "/modules/mod_", "/administrator/components/"),
        version_extractor=_joomla_version,
    ),
    _Signature(
        name="TYPO3",
        url_paths=("/typo3conf/", "/typo3temp/", "/fileadmin/"),
        cookie_prefixes=("fe_typo_user", "be_typo_user"),
        version_extractor=_typo3_version,
    ),
    _Signature(
        name="Adobe Experience Manager",
        url_paths=("/etc.clientlibs/", "/content/dam/", "/jcr:content"),
    ),
    _Signature(
        name="Magento",
        url_paths=("/pub/static/version", "/static/_cache/", "/skin/frontend/"),
        cookie_prefixes=("mage-cache-storage", "X-Magento-Vary"),
    ),
    _Signature(
        name="Sitecore",
        url_paths=("/sitecore/", "/-/media/"),
        cookie_prefixes=("SC_ANALYTICS_GLOBAL_COOKIE",),
    ),
    _Signature(
        name="Shopify",
        url_paths=(),  # no path signal — too generic ("/cart", "/products")
        host_suffixes=(".myshopify.com", "cdn.shopify.com"),
        header_names=("x-shopid", "x-shopify-stage"),
    ),
    _Signature(
        name="Wix",
        # parastorage.com / wixstatic.com are Wix's exclusive asset and
        # media CDNs, loaded by every Wix-hosted site regardless of the
        # custom domain it is served under. No version: Wix is a
        # continuously-deployed SaaS with no per-site version to expose.
        url_paths=(),
        host_suffixes=(".parastorage.com", ".wixstatic.com"),
    ),
    _Signature(
        name="Squarespace",
        # squarespace.com / squarespace-cdn.com / sqspcdn.com are
        # exclusively Squarespace's asset, media and component CDNs,
        # loaded by every Squarespace site. No per-site version (SaaS).
        url_paths=(),
        host_suffixes=(".squarespace.com", ".squarespace-cdn.com", ".sqspcdn.com"),
    ),
    _Signature(
        name="Weebly",
        # editmysite.com is Weebly's (Square's) exclusive asset CDN;
        # weebly.com hosts the published sites. No per-site version (SaaS).
        url_paths=(),
        host_suffixes=(".editmysite.com", ".weebly.com"),
    ),
    _Signature(
        name="Webflow",
        # website-files.com is Webflow's exclusive asset CDN; webflow.io
        # hosts published/staging sites; webflow.com fronts uploads
        # (uploads-ssl.webflow.com). No per-site version (SaaS).
        url_paths=(),
        host_suffixes=(".website-files.com", ".webflow.io", ".webflow.com"),
    ),
    _Signature(
        name="Jimdo",
        # jimstatic.com is Jimdo's exclusive asset/font/renderer CDN;
        # jimdo.systems is its analytics beacon. No per-site version (SaaS).
        url_paths=(),
        host_suffixes=(".jimstatic.com", ".jimdo.systems"),
    ),
    _Signature(
        name="Duda",
        # multiscreensite.com and cdn-website.com are Duda's exclusive
        # publishing CDN / runtime / image-proxy domains (regional
        # variants prefix the registrable domain, e.g.
        # eu-multiscreensite.com). No per-site version (SaaS).
        url_paths=(),
        host_suffixes=(".multiscreensite.com", "-multiscreensite.com",
                       ".cdn-website.com"),
    ),
    _Signature(
        name="Zyro / Hostinger",
        # zyrosite.com is the exclusive asset/media/font CDN for sites
        # built on Zyro / Hostinger Website Builder. No version (SaaS).
        url_paths=(),
        host_suffixes=(".zyrosite.com",),
    ),
)


# ---------------------------------------------------------------------------
# Detection entry point
# ---------------------------------------------------------------------------


def detect_cms(events: Iterable[RequestEvent]) -> CMSFingerprint | None:
    """Return the first platform whose signature matches any captured event.

    Returns ``None`` when no platform signature matches. The result is
    deterministic: signatures are tested in declaration order, and for
    each signature we walk the events in the order they were captured.
    """
    events_list = list(events)
    if not events_list:
        return None

    for sig in _SIGNATURES:
        match = _first_match(sig, events_list)
        if match is None:
            continue
        # Best-effort version: try the matching event first, then any
        # other event (meta-generator typically lives on the landing
        # page, not the asset URL that matched the path signature).
        version: str | None = None
        version_source: str | None = None
        if sig.version_extractor is not None:
            found = sig.version_extractor(match)
            if found is None:
                for ev in events_list:
                    if ev is match:
                        continue
                    found = sig.version_extractor(ev)
                    if found is not None:
                        break
            if found is not None:
                version, version_source = found
        evidence = _describe_match(sig, match)
        if version_source is not None:
            evidence = f"{evidence}; version from {version_source}"
        return CMSFingerprint(
            name=sig.name,
            version=version,
            confidence="certain",
            evidence=evidence,
        )
    return None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _first_match(sig: _Signature, events: list[RequestEvent]) -> RequestEvent | None:
    """Return the first event matching any of ``sig``'s rules."""
    for ev in events:
        if _event_matches(sig, ev):
            return ev
    return None


def _event_matches(sig: _Signature, ev: RequestEvent) -> bool:
    """Test one event against every rule on the signature."""
    url = ev.url or ""
    host = ev.host or ""
    for path in sig.url_paths:
        if path in url:
            return True
    for suffix in sig.host_suffixes:
        if host.endswith(suffix) or suffix in host:
            return True
    if sig.header_names or sig.header_prefixes:
        headers_lower = {
            k.lower(): v for k, v in (ev.response_headers or {}).items()
        }
        for name in sig.header_names:
            if name.lower() in headers_lower:
                return True
        for name, prefix in sig.header_prefixes:
            val = headers_lower.get(name.lower(), "")
            if val.lower().startswith(prefix.lower()):
                return True
    if sig.cookie_prefixes:
        set_cookie = _set_cookie_lines(ev)
        for prefix in sig.cookie_prefixes:
            if any(line.lower().startswith(prefix.lower() + "=") for line in set_cookie):
                return True
    return False


def _set_cookie_lines(ev: RequestEvent) -> list[str]:
    """Return the per-cookie Set-Cookie directives from this event's response.

    ``response_headers`` can carry a single string (joined with commas
    by some recorders) or a list. Either way, we split on ``\\n`` and
    return the lines so the caller can match cookie-name prefixes.
    """
    raw = (ev.response_headers or {}).get("set-cookie") or \
          (ev.response_headers or {}).get("Set-Cookie") or ""
    if isinstance(raw, list):
        return raw
    return [line.strip() for line in raw.split("\n") if line.strip()]


def _describe_match(sig: _Signature, ev: RequestEvent) -> str:
    """Build a one-line evidence string for the report."""
    url = ev.url or ""
    for path in sig.url_paths:
        if path in url:
            return f"URL path {path!r} observed"
    host = ev.host or ""
    for suffix in sig.host_suffixes:
        if host.endswith(suffix) or suffix in host:
            return f"host {host} matches {suffix!r}"
    headers_lower = {
        k.lower(): v for k, v in (ev.response_headers or {}).items()
    }
    for name in sig.header_names:
        if name.lower() in headers_lower:
            return f"response header {name!r} present"
    for name, prefix in sig.header_prefixes:
        if headers_lower.get(name.lower(), "").lower().startswith(prefix.lower()):
            return f"response header {name}: {prefix}…"
    for prefix in sig.cookie_prefixes:
        return f"Set-Cookie {prefix!r} present"
    return "signature match"
