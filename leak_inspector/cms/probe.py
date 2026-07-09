"""Active version probe for detected CMSes.

After passive detection identifies the platform (see :mod:`.detect`),
this module fetches the *single* most-reliable version-revealing file
that the CMS exposes. The probe runs at analysis time — bundles
captured in the field stay pristine.

Per-platform probe URLs are chosen for maximum signal vs. minimum
intrusion. None of these are admin or write endpoints; each is a
public, static or near-static path the platform ships by default:

* **Joomla** — ``/administrator/manifests/files/joomla.xml``
  (canonical manifest, contains ``<version>``).
* **WordPress** — ``/feed/`` (RSS endpoint; ``<generator>`` carries
  ``wordpress.org/?v=X.Y.Z``).
* **Drupal** — ``/CHANGELOG.txt`` for D7, falls back to
  ``/core/CHANGELOG.txt`` for D8+. First line is ``Drupal X.Y.Z, …``.
* **Magento** — ``/magento_version`` (M2 introduced this endpoint;
  returns plain text ``Magento/X.Y.Z (edition)``).

Enterprise / hosted platforms (Adobe Experience Manager, Sitecore,
Shopify) have no comparable public version endpoint and are
explicitly skipped — probing them would be guessing.

The HTTP fetcher is injectable for tests; the default reaches the
network with a short timeout, a small max-body cap, and a User-Agent
that identifies this project as an audit tool.
"""

from __future__ import annotations

import re
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Callable
from urllib.parse import urlparse

from ..safe_net import build_safe_opener, is_public_url


#: Sent on every probe request so site admins can see in their logs who's
#: probing and why. Mentions both the tool and the purpose so the request
#: doesn't look like a generic recon scan.
PROBE_USER_AGENT = (
    "leak_inspector/0.1.0 (CMS version audit probe; +https://belibre.be)"
)

#: Probe HTTP timeout. Short, because failure is informative (and common —
#: many sites 404 these paths, return Cloudflare challenges, etc.).
_PROBE_TIMEOUT_SECONDS = 5

#: Cap on body bytes we'll read. The patterns we extract live in the first
#: few hundred bytes of every supported response; reading more wastes
#: bandwidth and exposes us to slowloris-style responses.
_PROBE_MAX_BYTES = 64 * 1024


# ---------------------------------------------------------------------------
# Per-CMS probe specification
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _Probe:
    """One platform's probe spec: list of candidate paths + a version regex.

    Paths are tried in order; the first hit wins. Each path uses the
    same regex (the response shape is similar across the fallbacks —
    e.g. Drupal's two changelog locations share the ``Drupal X.Y.Z``
    leading line).
    """

    platform: str
    paths: tuple[str, ...]
    version_re: re.Pattern[str]


_PROBES: tuple[_Probe, ...] = (
    _Probe(
        platform="Joomla",
        paths=("/administrator/manifests/files/joomla.xml",),
        version_re=re.compile(r"<version>\s*([\d.]+)\s*</version>"),
    ),
    _Probe(
        platform="WordPress",
        paths=("/feed/", "/?feed=rss2", "/comments/feed/"),
        version_re=re.compile(r"wordpress\.org/\?v=([\d.]+)"),
    ),
    _Probe(
        platform="Drupal",
        paths=("/CHANGELOG.txt", "/core/CHANGELOG.txt"),
        version_re=re.compile(r"^Drupal\s+([\d.]+)", re.MULTILINE),
    ),
    _Probe(
        platform="Magento",
        paths=("/magento_version",),
        version_re=re.compile(r"Magento/([\d.]+)"),
    ),
)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


Fetcher = Callable[[str], str | None]


def probe_version(
    platform: str, base_url: str, *, fetcher: Fetcher | None = None,
) -> str | None:
    """Fetch the platform's canonical version file and extract the version.

    Returns the version string on success, or ``None`` when the
    platform isn't probeable, the fetch failed, or the response didn't
    match the expected pattern. ``base_url`` may be any URL on the
    target site — only its origin (scheme + netloc) is used; the path
    is replaced with the probe path.
    """
    probe = _probe_for(platform)
    if probe is None:
        return None
    do_fetch: Fetcher = fetcher or _http_get
    for url in _candidate_urls(probe, base_url):
        body = do_fetch(url)
        if not body:
            continue
        m = probe.version_re.search(body)
        if m:
            return m.group(1)
    return None


def probe_url_for(platform: str, base_url: str) -> tuple[str, ...]:
    """Return the candidate probe URLs for ``platform`` (empty when unprobeable).

    Exposed so callers can describe the probe in the report ("version
    probed via /administrator/manifests/files/joomla.xml") without
    re-deriving the URL.
    """
    probe = _probe_for(platform)
    if probe is None:
        return ()
    return tuple(_candidate_urls(probe, base_url))


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------


def _probe_for(platform: str) -> _Probe | None:
    """Return the :class:`_Probe` for ``platform`` if one exists."""
    for p in _PROBES:
        if p.platform == platform:
            return p
    return None


def _candidate_urls(probe: _Probe, base_url: str) -> list[str]:
    """Compose absolute URLs from the probe's paths and the target's origin."""
    parsed = urlparse(base_url)
    if not parsed.scheme or not parsed.netloc:
        return []
    origin = f"{parsed.scheme}://{parsed.netloc}"
    return [origin + path for path in probe.paths]


#: Shared opener that re-validates every redirect ``Location`` against
#: ``is_public_url`` before following — see ``leak_inspector.safe_net``.
_OPENER = build_safe_opener()


def _http_get(url: str) -> str | None:
    """Default fetcher: one-shot GET with a short timeout and capped body.

    Returns the decoded body text on 2xx with a non-empty body, or
    ``None`` on any error condition (4xx, 5xx, timeout, DNS failure,
    TLS failure, redirect chain dropping origin, etc.). Probing must
    fail silently — the caller can't take corrective action.

    Refuses URLs whose scheme is not ``http``/``https`` or whose host
    resolves into private / loopback / link-local / reserved space.
    See ``leak_inspector.safe_net`` for the threat model.
    """
    if not is_public_url(url):
        return None
    req = urllib.request.Request(
        url, headers={"User-Agent": PROBE_USER_AGENT},
    )
    try:
        with _OPENER.open(req, timeout=_PROBE_TIMEOUT_SECONDS) as resp:
            if resp.status != 200:
                return None
            raw = resp.read(_PROBE_MAX_BYTES)
            if not raw:
                return None
            return raw.decode("utf-8", errors="replace")
    except (urllib.error.URLError, TimeoutError, OSError, ValueError):
        return None


__all__ = [
    "PROBE_USER_AGENT",
    "probe_url_for",
    "probe_version",
]
