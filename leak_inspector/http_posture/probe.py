"""HTTP/HTTPS probe + transport-posture data model.

The probe runs at analysis time and asks four questions of the
captured site's host(s):

* Does HTTP respond? With what status, and where does the redirect
  chain end?
* Does HTTPS respond? Same.
* Same questions for the alternate host (apex ↔ www) when applicable.

A site is considered "responding" on a scheme when *any* HTTP-layer
response comes back — including 3xx, 4xx, and 5xx. A connection
refused, DNS failure, or TLS handshake error counts as "not
responding". This distinction matches the auditor's intent: "HTTPS is
broken" means the server can't be reached over TLS at all, not "the
home page is 500-ing".

The HTTP fetcher is injected for tests so the unit suite is hermetic;
the default fetcher uses ``urllib`` with a short timeout and a small
read budget.
"""

from __future__ import annotations

import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Callable
from urllib.parse import urlparse

from ..safe_net import build_safe_opener, is_public_url


#: One-line User-Agent so the site's logs can attribute these probes.
PROBE_USER_AGENT = (
    "leak_inspector/0.1.0 (transport posture audit probe; +https://belibre.be)"
)

#: Per-request timeout. Short, because failure is informative.
_PROBE_TIMEOUT_SECONDS = 5


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class HostProbe:
    """Result of probing one host over both schemes."""

    host: str
    http_responded: bool
    https_responded: bool
    http_status: int | None
    https_status: int | None
    http_final_url: str | None
    https_final_url: str | None

    @property
    def http_redirects_to_https(self) -> bool:
        """``True`` when the HTTP request's redirect chain ended at HTTPS."""
        if not self.http_responded or self.http_final_url is None:
            return False
        return self.http_final_url.lower().startswith("https://")

    @property
    def resolves(self) -> bool:
        """``True`` when either scheme produced a response."""
        return self.http_responded or self.https_responded


@dataclass(frozen=True)
class TransportPosture:
    """Captured site's transport posture.

    ``primary`` is the host the visitor actually landed on (taken from
    the manifest's ``landing_url``). ``alternate`` is the other variant
    of the apex/www pair when the primary is at ``<base_domain>`` or
    ``www.<base_domain>``; otherwise ``None`` (subdomain sites don't
    get apex/www testing because the apex usually belongs to a
    different organisation).
    """

    primary: HostProbe
    alternate: HostProbe | None


# ---------------------------------------------------------------------------
# Public probe entry point
# ---------------------------------------------------------------------------


Fetcher = Callable[[str], dict | None]


def probe_transport(
    *, landing_url: str, base_domain: str,
    fetcher: Fetcher | None = None,
) -> TransportPosture | None:
    """Probe the captured host (and its apex/www alternate when applicable).

    Returns ``None`` if the bundle didn't carry enough information to
    pick a host to probe (no landing URL or no base_domain), or if the
    captured URL's host can't be parsed.
    """
    if not landing_url or not base_domain:
        return None
    primary_host = urlparse(landing_url).hostname
    if not primary_host:
        return None
    do_fetch: Fetcher = fetcher or _http_get

    # Run all probes (2 for subdomain sites, 4 for apex/www sites) in
    # parallel: each is an independent HTTP request and the worst-case
    # connection timeout is identical, so wall-clock collapses to the
    # slowest single probe rather than the sum of all four. The pool
    # is sized to the worst case (4) since that's still a small number
    # of concurrent connections.
    alternate_host = _alternate_host_for(primary_host, base_domain)
    hosts: list[str] = [primary_host]
    if alternate_host:
        hosts.append(alternate_host)
    urls = [
        (host, scheme, f"{scheme}://{host}/")
        for host in hosts for scheme in ("http", "https")
    ]
    results: dict[tuple[str, str], dict | None] = {}
    with ThreadPoolExecutor(max_workers=len(urls)) as pool:
        future_to_key = {
            pool.submit(do_fetch, url): (host, scheme)
            for host, scheme, url in urls
        }
        for future, key in future_to_key.items():
            results[key] = future.result()

    primary = _build_host_probe(primary_host, results)
    alternate = (
        _build_host_probe(alternate_host, results) if alternate_host else None
    )
    return TransportPosture(primary=primary, alternate=alternate)


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------


def _alternate_host_for(host: str, base_domain: str) -> str | None:
    """If ``host`` is the apex or www of ``base_domain``, return the other.

    Returns ``None`` for subdomain sites — testing apex/www of a
    different organisation's domain would be both wrong and noisy.
    """
    if host == base_domain:
        return f"www.{base_domain}"
    if host == f"www.{base_domain}":
        return base_domain
    return None


def _build_host_probe(
    host: str, results: dict[tuple[str, str], dict | None],
) -> HostProbe:
    """Assemble one :class:`HostProbe` from the parallel-probe result map."""
    http = results.get((host, "http"))
    https = results.get((host, "https"))
    return HostProbe(
        host=host,
        http_responded=http is not None,
        https_responded=https is not None,
        http_status=(http or {}).get("status"),
        https_status=(https or {}).get("status"),
        http_final_url=(http or {}).get("final_url"),
        https_final_url=(https or {}).get("final_url"),
    )


#: Shared opener that re-validates every redirect ``Location`` against
#: ``is_public_url`` before following — see ``leak_inspector.safe_net``.
_OPENER = build_safe_opener()


def _http_get(url: str) -> dict | None:
    """Default fetcher: one-shot GET, follow redirects, capture final URL.

    Returns ``{"status": int, "final_url": str}`` on any HTTP-layer
    response (including 4xx / 5xx — server *did* respond). Returns
    ``None`` on connection refused / DNS failure / timeout / TLS
    error — anything that means the server couldn't be reached over
    this scheme.

    Refuses URLs whose scheme is not ``http``/``https`` or whose host
    resolves into private / loopback / link-local / reserved space; a
    refused URL is reported as "didn't respond". A redirect into
    private space is not followed — the 3xx surfaces to the caller as
    the final response (no second request is issued).
    """
    if not is_public_url(url):
        return None
    req = urllib.request.Request(
        url, headers={"User-Agent": PROBE_USER_AGENT},
    )
    try:
        with _OPENER.open(req, timeout=_PROBE_TIMEOUT_SECONDS) as resp:
            # ``resp.url`` reflects redirects already followed by urllib.
            return {"status": resp.status, "final_url": resp.url}
    except urllib.error.HTTPError as exc:
        # 4xx / 5xx — the server responded, just with an error status.
        # That still counts as "scheme works" for our purposes.
        return {"status": exc.code, "final_url": exc.url}
    except (urllib.error.URLError, TimeoutError, OSError, ValueError):
        return None


__all__ = [
    "HostProbe",
    "PROBE_USER_AGENT",
    "TransportPosture",
    "probe_transport",
]
