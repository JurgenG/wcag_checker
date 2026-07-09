"""Tests for page-context-aware first/third-party classification.

A third party is relative to the page(s) the visitor was actually on
during the session, not the single session-start domain. Top-level
browsing contexts (tabs / popups — UUID context ids) are pages the
visitor visited and are first-party; child frames (iframes — numeric
context ids) are embedded and stay third-party relative to the page.
"""

from __future__ import annotations

import pytest

from leak_inspector.analysis import analyze_events
from leak_inspector.analysis.runner import Analysis
from leak_inspector.bundle.manifest import Manifest
from leak_inspector.events import (
    NavigationEvent,
    RequestEvent,
    StorageSnapshotEvent,
    TYPE_NAVIGATION,
    TYPE_REQUEST,
    TYPE_STORAGE_SNAPSHOT,
)


def _manifest(
    *, target: str, landing: str, base: str,
) -> Manifest:
    return Manifest(
        bundle_schema=1, tool="leak_inspector", tool_version="0.1.0",
        session_id="s", started_at="t1", ended_at="t2",
        target_url=target, base_domain=base, browser={}, profile="p",
        landing_url=landing,
    )


def _nav(event_id: int, context_id, url: str) -> NavigationEvent:
    return NavigationEvent(
        event_id=event_id, timestamp="t", type=TYPE_NAVIGATION,
        context_id=context_id, payload={"url": url}, url=url,
    )


def _req(event_id: int, context_id, host: str) -> RequestEvent:
    return RequestEvent(
        event_id=event_id, timestamp="t", type=TYPE_REQUEST,
        context_id=context_id, payload={},
        method="GET", url=f"https://{host}/x", host=host, headers={},
        request_body=None, initiator=None, response_status=200,
        response_mime=None, response_headers={},
    )


def _storage(event_id: int, origin: str) -> StorageSnapshotEvent:
    """Synthetic storage snapshot — only ``origin`` matters for these tests."""
    return StorageSnapshotEvent(
        event_id=event_id, timestamp="t", type=TYPE_STORAGE_SNAPSHOT,
        context_id=None, payload={"origin": origin},
        origin=origin, kind="local", entries=[],
    )


# --- visited_pages collection (runner) --------------------------------------


def test_visited_pages_collects_top_level_navigations() -> None:
    """Top-level (UUID-context) navigations are recorded as visited pages."""
    m = _manifest(target="https://awel.be", landing="https://awel.be/", base="awel.be")
    events = [
        _nav(1, "d2488ce1-2e09-4a3d-a3c0-c1549252ebbf", "https://awel.be/"),
        _nav(2, "c8c2bc4f-eadb-4e5d-902a-b0f9d550053d", "https://awel.sittool.net/chat"),
        _req(3, "d2488ce1-2e09-4a3d-a3c0-c1549252ebbf", "example.com"),
    ]
    analysis = analyze_events(m, events)
    assert "https://awel.be/" in analysis.visited_pages
    assert "https://awel.sittool.net/chat" in analysis.visited_pages


def test_visited_pages_excludes_iframe_navigations() -> None:
    """Child-frame (numeric-context) navigations are NOT visited pages."""
    m = _manifest(target="https://awel.be", landing="https://awel.be/", base="awel.be")
    events = [
        _nav(1, "d2488ce1-2e09-4a3d-a3c0-c1549252ebbf", "https://awel.be/"),
        # Numeric context id == an iframe (cookiebot CMP).
        _nav(2, "19327352834", "https://consentcdn.cookiebot.com/sdk/bc-v4.min.html"),
        _nav(3, "15032385539", "https://www.google.com/recaptcha/api2/anchor"),
    ]
    analysis = analyze_events(m, events)
    assert analysis.visited_pages == ["https://awel.be/"]


def test_visited_pages_dedups_and_preserves_order() -> None:
    m = _manifest(target="https://awel.be", landing="https://awel.be/", base="awel.be")
    events = [
        _nav(1, "ctx-aaaa-bbbb-cccc-dddd-eeee", "https://awel.be/"),
        _nav(2, "ctx-aaaa-bbbb-cccc-dddd-eeee", "https://awel.be/themas"),
        _nav(3, "ctx-aaaa-bbbb-cccc-dddd-eeee", "https://awel.be/"),  # repeat
    ]
    analysis = analyze_events(m, events)
    assert analysis.visited_pages == ["https://awel.be/", "https://awel.be/themas"]


# --- first_party_domains ----------------------------------------------------


def test_first_party_domains_includes_entry_and_visited() -> None:
    m = _manifest(
        target="https://museumpas.be",
        landing="https://www.museumpassmusees.be/nl",
        base="museumpassmusees.be",
    )
    analysis = Analysis(
        manifest=m,
        visited_pages=["https://museumpas.be/", "https://www.museumpassmusees.be/nl/aanbod"],
    )
    fp = analysis.first_party_domains()
    assert "museumpas.be" in fp          # redirect origin (target)
    assert "museumpassmusees.be" in fp   # landing / base


# --- is_third_party_host ----------------------------------------------------


def test_redirect_origin_is_first_party() -> None:
    """museumpas.be (the entry the operator typed) is not a third party."""
    m = _manifest(
        target="https://museumpas.be",
        landing="https://www.museumpassmusees.be/nl",
        base="museumpassmusees.be",
    )
    analysis = Analysis(manifest=m)
    assert analysis.is_third_party_host("museumpas.be") is False


def test_visited_top_level_page_is_first_party() -> None:
    """awel.sittool.net (a top-level page the visitor navigated into) is first-party."""
    m = _manifest(target="https://awel.be", landing="https://awel.be/", base="awel.be")
    analysis = Analysis(manifest=m, visited_pages=["https://awel.sittool.net/chat"])
    assert analysis.is_third_party_host("awel.sittool.net") is False


def test_iframe_widget_stays_third_party() -> None:
    """A genuine embedded tracker (cookiebot) is third-party even if a sibling nav existed."""
    m = _manifest(target="https://awel.be", landing="https://awel.be/", base="awel.be")
    analysis = Analysis(manifest=m, visited_pages=["https://awel.sittool.net/chat"])
    assert analysis.is_third_party_host("consentcdn.cookiebot.com") is True


def test_genuine_third_party_host() -> None:
    m = _manifest(
        target="https://museumpas.be",
        landing="https://www.museumpassmusees.be/nl",
        base="museumpassmusees.be",
    )
    analysis = Analysis(manifest=m, visited_pages=["https://www.museumpassmusees.be/nl"])
    assert analysis.is_third_party_host("www.youtube.com") is True


def test_operator_family_still_first_party() -> None:
    """Operator-family awareness is preserved: s-microsoft.com vs microsoft.com."""
    m = _manifest(target="https://microsoft.com", landing="https://microsoft.com/", base="microsoft.com")
    analysis = Analysis(manifest=m)
    assert analysis.is_third_party_host("c.s-microsoft.com") is False


def test_empty_host_not_third_party() -> None:
    m = _manifest(target="https://awel.be", landing="https://awel.be/", base="awel.be")
    analysis = Analysis(manifest=m)
    assert analysis.is_third_party_host("") is False


# --- storage-snapshot origins as first-party signal ------------------------
#
# Scenario from real captures: a Magento multi-store redirect chain
# (sokken.nl → boxers.nl → zwembroeken.nl). BiDi top-level
# ``NavigationEvent`` emission is occasionally missed for the final
# hop, but the capture pipeline still snapshots ``localStorage`` for
# every top-level origin the browser loaded — including the page
# whose nav event was lost. Folding those origins into
# ``first_party_domains`` recovers the correct classification.


def test_storage_snapshot_origin_becomes_first_party() -> None:
    """An origin with a storage snapshot but no nav event is still first-party."""
    m = _manifest(
        target="https://sokken.nl",
        landing="https://www.sokken.nl/",
        base="sokken.nl",
    )
    events = [
        _nav(1, "ctx-uuid-aaaa-bbbb-cccc-dddd", "https://www.sokken.nl/"),
        # No NavigationEvent for zwembroeken.nl — only a storage snapshot.
        _storage(2, "https://www.zwembroeken.nl"),
        _req(3, "ctx-uuid-aaaa-bbbb-cccc-dddd", "www.zwembroeken.nl"),
    ]
    analysis = analyze_events(m, events)
    assert "zwembroeken.nl" in analysis.first_party_domains()
    assert analysis.is_third_party_host("www.zwembroeken.nl") is False


def test_storage_snapshot_origin_runs_through_registrable_extraction() -> None:
    """An origin like ``https://www.boxers.nl`` contributes ``boxers.nl`` as eTLD+1."""
    m = _manifest(
        target="https://sokken.nl",
        landing="https://www.sokken.nl/",
        base="sokken.nl",
    )
    events = [_storage(1, "https://www.boxers.nl")]
    analysis = analyze_events(m, events)
    fp = analysis.first_party_domains()
    assert "boxers.nl" in fp


def test_storage_snapshot_origins_collected_per_unique_origin() -> None:
    """Repeated snapshots for the same origin contribute one entry."""
    m = _manifest(
        target="https://sokken.nl",
        landing="https://www.sokken.nl/",
        base="sokken.nl",
    )
    events = [
        _storage(1, "https://www.boxers.nl"),
        _storage(2, "https://www.boxers.nl"),
        _storage(3, "https://www.boxers.nl"),
    ]
    analysis = analyze_events(m, events)
    assert analysis.storage_snapshot_origins == {"https://www.boxers.nl"}


def test_storage_snapshot_with_empty_origin_ignored() -> None:
    """A snapshot with an empty origin string must not poison the first-party set."""
    m = _manifest(target="https://awel.be", landing="https://awel.be/", base="awel.be")
    events = [_storage(1, "")]
    analysis = analyze_events(m, events)
    # The empty string contributes nothing; only the manifest's base is first-party.
    assert "awel.be" in analysis.first_party_domains()
    # A genuine third-party host stays third-party.
    assert analysis.is_third_party_host("www.youtube.com") is True


def test_storage_snapshot_origin_does_not_clear_genuine_third_party() -> None:
    """Folding storage origins must not over-broaden first-party to actual trackers."""
    m = _manifest(target="https://sokken.nl", landing="https://www.sokken.nl/", base="sokken.nl")
    # Only sokken.nl + boxers.nl get storage snapshots — google-analytics doesn't.
    events = [
        _storage(1, "https://www.sokken.nl"),
        _storage(2, "https://www.boxers.nl"),
    ]
    analysis = analyze_events(m, events)
    assert analysis.is_third_party_host("www.google-analytics.com") is True
    assert analysis.is_third_party_host("connect.facebook.net") is True
