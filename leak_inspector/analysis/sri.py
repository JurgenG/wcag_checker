"""Detect third-party subresources loaded without Subresource Integrity.

A page that pulls a ``<script src>`` or ``<link rel=stylesheet>`` from a
third-party host **without** an ``integrity`` hash trusts that host
completely: if the host (or its CDN) is compromised, attacker-controlled
code runs in the first-party origin — JavaScript directly, CSS via
selector-based exfiltration and UI redressing. An ``integrity`` hash
makes the browser refuse a body that doesn't match, closing that gap.

Pure and offline: this operates on the per-page subresource index
recorded at capture (``page_source*.scripts.json`` rows of ``{url,
integrity, crossorigin, kind, sha256, status}``; rows from bundles that
predate stylesheet enumeration carry no ``kind`` and are scripts) plus
an injected ``is_third_party`` predicate, so it imports neither the
analysis runner nor the bundle reader. "Third-party" is the caller's
operator-family-aware notion (an operator's own subdomain / CDN is *not*
flagged), which is tighter than literal cross-origin and matches the
rest of the analysis.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Iterable
from urllib.parse import urlsplit


@dataclass(frozen=True)
class MissingSRI:
    """One third-party subresource referenced without an SRI hash.

    ``kind`` is ``"script"`` (``<script src>``) or ``"stylesheet"``
    (``<link rel=stylesheet>``).
    """

    url: str
    host: str
    crossorigin: str | None = None
    kind: str = "script"


@dataclass(frozen=True)
class ProtectedSRI:
    """One third-party subresource referenced *with* an SRI hash.

    The positive counterpart of :class:`MissingSRI`: the operator pinned
    the body of a third-party ``<script src>`` / ``<link rel=stylesheet>``
    with an ``integrity`` hash, so a compromised CDN cannot swap in
    attacker code. ``kind`` is ``"script"`` or ``"stylesheet"``.
    """

    url: str
    host: str
    crossorigin: str | None = None
    kind: str = "script"


def detect_missing_sri(
    scripts: Iterable[dict],
    is_third_party: Callable[[str], bool],
) -> list[MissingSRI]:
    """Flag third-party subresources that carry no ``integrity`` hash.

    ``scripts`` is the captured index, aggregated across every
    ``page_source*.scripts.json`` in the bundle. ``is_third_party`` decides,
    per host, whether a subresource is operator-controlled (skipped) or
    third-party (a supply-chain risk).

    An entry is flagged when it has a usable URL host, no truthy
    ``integrity``, and ``is_third_party(host)`` is true. Results are
    deduplicated by URL, preserving first-seen order.
    """
    flagged: list[MissingSRI] = []
    seen: set[str] = set()
    for entry in scripts:
        url = entry.get("url")
        if not url or url in seen:
            continue
        if entry.get("integrity"):
            continue
        host = urlsplit(url).hostname or ""
        if not host or not is_third_party(host):
            continue
        seen.add(url)
        flagged.append(MissingSRI(
            url=url,
            host=host,
            crossorigin=entry.get("crossorigin"),
            kind=entry.get("kind") or "script",
        ))
    return flagged


def detect_protected_sri(
    scripts: Iterable[dict],
    is_third_party: Callable[[str], bool],
) -> list[ProtectedSRI]:
    """Flag third-party subresources that *do* carry an ``integrity`` hash.

    The positive counterpart of :func:`detect_missing_sri`, over the same
    captured index and ``is_third_party`` predicate. An entry is flagged
    when it has a usable URL host, a truthy ``integrity``, and
    ``is_third_party(host)`` is true. Results are deduplicated by URL,
    preserving first-seen order.
    """
    protected: list[ProtectedSRI] = []
    seen: set[str] = set()
    for entry in scripts:
        url = entry.get("url")
        if not url or url in seen:
            continue
        if not entry.get("integrity"):
            continue
        host = urlsplit(url).hostname or ""
        if not host or not is_third_party(host):
            continue
        seen.add(url)
        protected.append(ProtectedSRI(
            url=url,
            host=host,
            crossorigin=entry.get("crossorigin"),
            kind=entry.get("kind") or "script",
        ))
    return protected
