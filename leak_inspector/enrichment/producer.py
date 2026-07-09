# leak_inspector — record what data a website leaks during a real
# human-driven browsing session.
# Copyright (C) 2026 Jurgen Gaeremyn
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

"""Enrichment producer: run the live-network phase, store it in the zip.

:func:`enrich_bundle` is the one entry point: read the bundle's
manifest + request hosts, run the lookups (DNS posture, transport
probes, CMS version probe, per-host IP/ASN/geo), and write the result
as the bundle's ``enrichment.json`` entry. Called by the capture CLI
immediately after the bundle is written (contemporaneous evidence),
and by ``leak-inspector enrich`` for retrofits / refreshes.

Soft-fail by design: each section is attempted independently; a
failing lookup leaves its section ``None`` and pushes a plain-language
message onto :attr:`Enrichment.errors` instead of raising. The capture
is never lost to a flaky resolver.

Every network-touching step is an injectable seam so tests stay
hermetic; the defaults are the live implementations.
"""

from __future__ import annotations

import shutil
import tempfile
import zipfile
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

import tldextract

from ..bundle.reader import BundleReader
from ..dns_posture.types import IPInfo
from ..events import RequestEvent
from .artifact import (
    ENRICHMENT_SECTIONS,
    ENRICHMENT_VERSION,
    ENRICHMENT_ZIP_ENTRY,
    CMSVersionProbe,
    Enrichment,
    enrichment_from_json,
    enrichment_to_json,
)

#: Canonical section id -> the :class:`Enrichment` attribute it fills.
_SECTION_ATTR = {
    "dns": "dns_posture",
    "transport": "transport_posture",
    "tls": "tls_posture",
    "cms-probe": "cms_probe",
    "security-txt": "security_txt",
    "hosts": "host_ipinfo",
}

#: Canonical section id -> the prefixes its soft-fail messages start
#: with. A selective refresh prunes the refreshed section's stale errors
#: by matching these, leaving other sections' warnings intact.
_SECTION_ERROR_PREFIXES = {
    "dns": ("DNS posture",),
    "transport": ("transport probe",),
    "tls": ("TLS probe",),
    "cms-probe": ("CMS version probe",),
    "security-txt": ("security.txt probe",),
    "hosts": ("host IP enrichment",),
}

#: Cap on distinct hosts enriched per bundle. Enrichment covers *all*
#: request hosts (the analysis layer later picks the ones it needs), so
#: a hostile bundle fabricating thousands of hostnames must not fan out
#: unbounded DNS + WHOIS queries. Sorted-prefix selection keeps the
#: covered set deterministic.
ENRICH_ALL_HOSTS_CAP = 200

#: Thread-pool width for the per-host lookups (network-bound).
_HOST_ENRICH_WORKERS = 8


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _is_public_registrable_domain(name: str) -> bool:
    """Return ``True`` when ``name`` is a public registrable domain.

    The DNS-posture lookup hands ``base_domain`` straight to the
    analyst's resolver, and ``base_domain`` is an untrusted manifest
    field (bundles are shared). Refuse anything without a public suffix —
    ``localhost``, bare labels, raw IP literals, internal TLDs — so a
    hostile bundle cannot use the resolver for reconnaissance against a
    name of its choosing. Public-suffix membership is decided by the
    Public Suffix List via :mod:`tldextract` (already the project's
    first-/third-party classifier).
    """
    if not name:
        return False
    ext = tldextract.extract(name)
    return bool(ext.domain and ext.suffix)


# --- default (live) seam implementations --------------------------------------


def _live_dns_lookup(domain: str):
    from ..dns_posture import lookup
    return lookup(domain)


def _live_transport_prober(*, landing_url: str, base_domain: str, fetcher=None):
    """``fetcher`` passes through to :func:`probe_transport`'s seam (tests)."""
    from ..http_posture.probe import probe_transport
    return probe_transport(
        landing_url=landing_url, base_domain=base_domain, fetcher=fetcher,
    )


def _live_cms_prober(events, base_url: str, *, fetcher=None) -> CMSVersionProbe | None:
    """Passive-detect the platform, then probe its version file.

    Mirrors the decision logic the analysis layer used when it still
    probed live: no platform → nothing to probe; version already found
    passively → no probe needed (offline analysis re-detects passively
    on its own); platform without version → probe, recording a
    ``version=None`` result when the file is hardened/removed.

    ``fetcher`` passes through to :func:`~leak_inspector.cms.probe
    .probe_version`'s existing injection seam (tests).
    """
    from ..cms.detect import detect_cms
    from ..cms.probe import probe_url_for, probe_version

    fingerprint = detect_cms(events)
    if fingerprint is None or fingerprint.version is not None:
        return None
    if not base_url:
        return None
    candidates = probe_url_for(fingerprint.name, base_url)
    if not candidates:
        return None  # platform isn't probeable (AEM / Sitecore / …)
    version = probe_version(fingerprint.name, base_url, fetcher=fetcher)
    return CMSVersionProbe(
        platform=fingerprint.name, version=version, probe_url=candidates[0],
    )


def _live_security_txt_prober(host: str):
    from ..http_posture.security_txt import probe_security_txt
    return probe_security_txt(host)


def _live_tls_prober(host: str):
    from ..http_posture.tls import probe_tls
    return probe_tls(host)


def _live_hosts_enricher(hosts: list[str]) -> dict[str, IPInfo | None]:
    from ..dns_posture.geoip import open_country_reader
    from ..dns_posture.sovereignty import enrich_host

    geo_reader = open_country_reader()
    try:
        with ThreadPoolExecutor(max_workers=_HOST_ENRICH_WORKERS) as pool:
            results = pool.map(
                lambda host: enrich_host(host, geo_reader), hosts
            )
            return dict(zip(hosts, results))
    finally:
        if geo_reader is not None:
            geo_reader.close()


# --- bundle I/O -----------------------------------------------------------------


def read_enrichment(bundle_path: Path | str) -> Enrichment | None:
    """Return the bundle's stored enrichment, or ``None`` when absent."""
    with zipfile.ZipFile(bundle_path) as zf:
        try:
            raw = zf.read(ENRICHMENT_ZIP_ENTRY)
        except KeyError:
            return None
    return enrichment_from_json(raw.decode("utf-8"))


def write_enrichment(bundle_path: Path | str, enrichment: Enrichment) -> None:
    """Write ``enrichment`` as the bundle's ``enrichment.json`` entry.

    First write appends to the existing zip (cheap). When the entry
    already exists (a ``--refresh``), the zip is rewritten without the
    old entry first so the bundle never carries duplicates.
    """
    bundle_path = Path(bundle_path)
    payload = enrichment_to_json(enrichment)
    with zipfile.ZipFile(bundle_path) as zf:
        has_existing = ENRICHMENT_ZIP_ENTRY in zf.namelist()
    if has_existing:
        _rewrite_without_entry(bundle_path, ENRICHMENT_ZIP_ENTRY)
    with zipfile.ZipFile(
        bundle_path, "a", compression=zipfile.ZIP_DEFLATED
    ) as zf:
        zf.writestr(ENRICHMENT_ZIP_ENTRY, payload)


def strip_enrichment(bundle_path: Path | str) -> bool:
    """Remove a bundle's enrichment entry; return whether one existed.

    The inverse of :func:`write_enrichment` — used to reset a bundle to
    its pre-enrichment state (tests that exercise first-enrichment
    semantics; operators discarding a bad artifact without --refresh).
    """
    bundle_path = Path(bundle_path)
    with zipfile.ZipFile(bundle_path) as zf:
        if ENRICHMENT_ZIP_ENTRY not in zf.namelist():
            return False
    _rewrite_without_entry(bundle_path, ENRICHMENT_ZIP_ENTRY)
    return True


def _rewrite_without_entry(bundle_path: Path, entry: str) -> None:
    """Rewrite the zip omitting ``entry`` (atomic same-directory replace)."""
    fd_path = tempfile.NamedTemporaryFile(
        dir=bundle_path.parent, suffix=".zip.tmp", delete=False,
    )
    tmp = Path(fd_path.name)
    fd_path.close()
    try:
        with zipfile.ZipFile(bundle_path) as src, zipfile.ZipFile(
            tmp, "w", compression=zipfile.ZIP_DEFLATED
        ) as dst:
            for info in src.infolist():
                if info.filename == entry:
                    continue
                dst.writestr(info, src.read(info.filename))
        shutil.move(tmp, bundle_path)
    finally:
        tmp.unlink(missing_ok=True)


# --- the producer ----------------------------------------------------------------


def _collect_request_data(bundle_path: Path | str):
    """One cheap pass over the bundle: manifest + request events + hosts."""
    with BundleReader(bundle_path) as bundle:
        manifest = bundle.manifest
        request_events = [
            e for e in bundle.events() if isinstance(e, RequestEvent)
        ]
    hosts = sorted({e.host for e in request_events if e.host})
    return manifest, request_events, hosts[:ENRICH_ALL_HOSTS_CAP]


# --- per-section probes (each soft-fails into ``(value, errors)``) --------------


def _enrich_dns(*, base_domain, dns_lookup_fn):
    """DNS posture of the first party; ``(None, [])`` when there is no
    base_domain, refusing non-public names (SSRF guard)."""
    if not base_domain:
        return None, []
    if not _is_public_registrable_domain(base_domain):
        return None, [
            f"DNS posture skipped: base_domain {base_domain!r} is not a "
            "public registrable domain"
        ]
    try:
        return dns_lookup_fn(base_domain), []
    except Exception as exc:
        return None, [f"DNS posture lookup failed: {exc}"]


def _enrich_transport(*, landing_url, base_domain, transport_prober):
    try:
        return transport_prober(
            landing_url=landing_url, base_domain=base_domain,
        ), []
    except Exception as exc:
        return None, [f"transport probe failed: {exc}"]


def _enrich_cms(*, request_events, landing_url, cms_prober):
    try:
        return cms_prober(request_events, landing_url), []
    except Exception as exc:
        return None, [f"CMS version probe failed: {exc}"]


def _enrich_security_txt(*, landing_host, security_txt_prober):
    if not landing_host:
        return None, []
    try:
        return security_txt_prober(landing_host), []
    except Exception as exc:
        return None, [f"security.txt probe failed: {exc}"]


def _enrich_tls(*, landing_host, tls_prober):
    if not landing_host:
        return None, []
    try:
        return tls_prober(landing_host), []
    except Exception as exc:
        return None, [f"TLS probe failed: {exc}"]


def _enrich_hosts(*, hosts, hosts_enricher):
    try:
        return hosts_enricher(hosts), []
    except Exception as exc:
        return {}, [f"host IP enrichment failed: {exc}"]


def _run_section(section, *, base_domain, landing_url, landing_host,
                 request_events, hosts, seams):
    """Run one section's probe; return ``(value, errors)``."""
    if section == "dns":
        return _enrich_dns(
            base_domain=base_domain, dns_lookup_fn=seams["dns_lookup_fn"],
        )
    if section == "transport":
        return _enrich_transport(
            landing_url=landing_url, base_domain=base_domain,
            transport_prober=seams["transport_prober"],
        )
    if section == "cms-probe":
        return _enrich_cms(
            request_events=request_events, landing_url=landing_url,
            cms_prober=seams["cms_prober"],
        )
    if section == "tls":
        return _enrich_tls(
            landing_host=landing_host, tls_prober=seams["tls_prober"],
        )
    if section == "security-txt":
        return _enrich_security_txt(
            landing_host=landing_host,
            security_txt_prober=seams["security_txt_prober"],
        )
    return _enrich_hosts(hosts=hosts, hosts_enricher=seams["hosts_enricher"])


def _prune_section_errors(errors: list[str], section: str) -> list[str]:
    """Drop the errors a refreshed section had recorded before."""
    prefixes = _SECTION_ERROR_PREFIXES[section]
    return [e for e in errors if not e.startswith(prefixes)]


def _landing_context(manifest):
    """Resolve the ``(base_domain, landing_url, landing_host)`` triple."""
    base_domain = manifest.base_domain or ""
    landing_url = manifest.landing_url or manifest.target_url or ""
    landing_host = urlsplit(landing_url).hostname or base_domain
    return base_domain, landing_url, landing_host


def enrich_bundle(
    bundle_path: Path | str,
    *,
    refresh: bool = False,
    sections: frozenset[str] | None = None,
    dns_lookup_fn=None,
    transport_prober=None,
    cms_prober=None,
    hosts_enricher=None,
    security_txt_prober=None,
    tls_prober=None,
    now_fn=None,
) -> tuple[Enrichment, bool]:
    """Enrich a capture bundle in place; return ``(enrichment, created)``.

    Three modes:

    * **idempotent** (default): when the bundle already carries an
      enrichment and ``refresh`` is false, the stored artifact is
      returned untouched (``created`` is ``False``) and **no network is
      touched** — re-running the pipeline must never silently re-probe.
    * **full refresh** (``refresh=True``): every section is re-probed
      and the artifact replaced; ``enriched_at`` and all
      :attr:`Enrichment.section_timestamps` are set to *now*.
    * **selective refresh** (``sections`` = canonical ids): only the
      named sections are re-probed and merged into the existing
      artifact; their per-section timestamps move to *now* while
      ``enriched_at`` and every other section stay put. Raises
      :class:`ValueError` when the bundle has no enrichment to merge
      into.

    Each section soft-fails independently: a failing lookup leaves its
    section ``None`` and records a plain-language message.
    """
    seams = {
        "dns_lookup_fn": dns_lookup_fn or _live_dns_lookup,
        "transport_prober": transport_prober or _live_transport_prober,
        "cms_prober": cms_prober or _live_cms_prober,
        "hosts_enricher": hosts_enricher or _live_hosts_enricher,
        "security_txt_prober": security_txt_prober or _live_security_txt_prober,
        "tls_prober": tls_prober or _live_tls_prober,
    }
    now_fn = now_fn or _utcnow

    if sections is not None:
        return _refresh_sections(bundle_path, sections, seams, now_fn), True

    if not refresh:
        existing = read_enrichment(bundle_path)
        if existing is not None:
            return existing, False

    manifest, request_events, hosts = _collect_request_data(bundle_path)
    base_domain, landing_url, landing_host = _landing_context(manifest)
    now = now_fn()
    enrichment = Enrichment(enriched_at=now)

    for section in ENRICHMENT_SECTIONS:
        value, errors = _run_section(
            section, base_domain=base_domain, landing_url=landing_url,
            landing_host=landing_host, request_events=request_events,
            hosts=hosts, seams=seams,
        )
        setattr(enrichment, _SECTION_ATTR[section], value)
        enrichment.section_timestamps[section] = now
        enrichment.errors.extend(errors)

    write_enrichment(bundle_path, enrichment)
    return enrichment, True


def _refresh_sections(bundle_path, sections, seams, now_fn) -> Enrichment:
    """Re-probe only ``sections`` and merge into the existing artifact."""
    existing = read_enrichment(bundle_path)
    if existing is None:
        raise ValueError(
            "nothing to refresh selectively — run a full enrich first"
        )

    manifest, request_events, hosts = _collect_request_data(bundle_path)
    base_domain, landing_url, landing_host = _landing_context(manifest)
    now = now_fn()

    for section in ENRICHMENT_SECTIONS:
        if section not in sections:
            continue
        value, errors = _run_section(
            section, base_domain=base_domain, landing_url=landing_url,
            landing_host=landing_host, request_events=request_events,
            hosts=hosts, seams=seams,
        )
        setattr(existing, _SECTION_ATTR[section], value)
        existing.section_timestamps[section] = now
        existing.errors = _prune_section_errors(existing.errors, section)
        existing.errors.extend(errors)

    # The merged artifact now carries per-section data — label it at the
    # current schema version rather than the one it was loaded as.
    existing.version = ENRICHMENT_VERSION
    write_enrichment(bundle_path, existing)
    return existing


__all__ = [
    "ENRICH_ALL_HOSTS_CAP",
    "enrich_bundle",
    "read_enrichment",
    "strip_enrichment",
    "write_enrichment",
]
