"""Decode the LCP/Icordis consent decision from its form POST.

The banner is server-rendered HTML; the decision is persisted in an
opaque server-set cookie, so no storage artifact decodes. The decision
POST itself (``action=acceptall`` / ``action=decline``) *is* the
machine-readable artifact — and ``hit.started_at`` is on the same
clock as every other hit, so the pre/post split needs no snapshot
boundary.

Synthetic hits: no committed capture carries a decision POST (bulk
captures never click; the beernem capture detected the banner only).
The hit shapes mirror what the registered ``lcp_icordis_consent``
module produces from the verified beernem form markup.
"""

from __future__ import annotations

from leak_inspector import modules  # noqa: F401  (registers detectors)
from leak_inspector.analysis.consent import derive_consent_state
from leak_inspector.events import StorageSnapshotEvent
from leak_inspector.modules.base import (
    CAT_CONSENT, CAT_IDENTIFIER, IMPACT_LOW, IMPACT_MEDIUM,
    Hit, ParamInfo,
)


def _param(key: str, value: str, category: str) -> ParamInfo:
    return ParamInfo(
        key=key, value=value, category=category, meaning="",
        privacy_impact=IMPACT_MEDIUM if category == CAT_IDENTIFIER
        else IMPACT_LOW,
        event_index=1,
    )


def _decision_post(action: str, *, ts: str) -> Hit:
    return Hit(
        module_id="lcp_icordis_consent",
        module_name="self-hosted consent banner (LCP/Icordis)",
        url="https://www.beernem.be/cookieverklaring?url=%2f",
        host="www.beernem.be",
        method="POST",
        response_status=302,
        started_at=ts,
        params=[_param("action", action, CAT_CONSENT)],
        events=[1],
    )


def _tracking_hit(ts: str, host: str = "stats.vendor.example") -> Hit:
    return Hit(
        module_id="ga4", module_name="Google Analytics 4",
        url=f"https://{host}/g/collect", host=host, method="POST",
        response_status=204, started_at=ts,
        params=[_param("cid", "123.456", CAT_IDENTIFIER)],
        events=[2],
    )


def _derive(*hits: Hit, snapshots=()):
    return derive_consent_state(list(snapshots), list(hits), lambda host: True)


# --- decision decoding -------------------------------------------------------


def test_acceptall_post_is_accepted() -> None:
    c = _derive(_decision_post("acceptall", ts="2026-06-01T10:00:05Z"))
    assert c.state == "accepted"
    assert c.source == "lcp_icordis_consent"
    assert c.granted == ()
    assert c.decided_at == "2026-06-01T10:00:05Z"


def test_decline_post_is_rejected() -> None:
    c = _derive(_decision_post("decline", ts="2026-06-01T10:00:05Z"))
    assert c.state == "rejected"
    assert c.source == "lcp_icordis_consent"


def test_last_decision_wins_first_timestamp_dates_it() -> None:
    """Visitor declines, then accepts via the manage page: the final
    choice is the state; the first decision moment bounds pre-consent."""
    c = _derive(
        _decision_post("decline", ts="2026-06-01T10:00:05Z"),
        _decision_post("acceptall", ts="2026-06-01T10:02:00Z"),
    )
    assert c.state == "accepted"
    assert c.decided_at == "2026-06-01T10:00:05Z"


def test_unknown_action_value_is_no_decision() -> None:
    """A hit whose action param decodes to nothing makes no claim."""
    c = _derive(_decision_post("save", ts="2026-06-01T10:00:05Z"))
    assert c.state == "unknown"


def test_banner_named_when_post_fires() -> None:
    c = _derive(_decision_post("decline", ts="2026-06-01T10:00:05Z"))
    assert "self-hosted consent banner (LCP/Icordis)" in c.cmp_names


def test_storage_artifact_takes_precedence() -> None:
    """When a cookie artifact also decodes (no known site has both),
    the persisted end state wins — existing behavior unchanged."""
    snapshot = StorageSnapshotEvent(
        event_id=3, timestamp="2026-06-01T10:00:07Z", type="storage",
        context_id=None, payload={}, origin="https://www.beernem.be",
        kind="cookie",
        entries=[{"key": "cookie-agreed", "value": "0"}],
    )
    c = _derive(
        _decision_post("acceptall", ts="2026-06-01T10:00:05Z"),
        snapshots=(snapshot,),
    )
    assert c.source == "eu_cookie_compliance"
    assert c.state == "rejected"


# --- pre/post split on the POST boundary -------------------------------------


def test_tracking_after_decline_is_post_reject() -> None:
    c = _derive(
        _decision_post("decline", ts="2026-06-01T10:00:05Z"),
        _tracking_hit("2026-06-01T10:00:09Z"),
    )
    assert c.post_reject_vendors == ("Google Analytics 4",)
    assert c.pre_decision_vendors == ()


def test_tracking_before_decision_is_pre_consent() -> None:
    c = _derive(
        _tracking_hit("2026-06-01T10:00:01Z"),
        _decision_post("decline", ts="2026-06-01T10:00:05Z"),
    )
    assert c.pre_decision_vendors == ("Google Analytics 4",)
    assert c.post_reject_vendors == ()


def test_decision_post_itself_is_not_an_offender() -> None:
    """The consent POST is the consent mechanism — exempt from the
    offender tally like every CMP module."""
    c = _derive(_decision_post("decline", ts="2026-06-01T10:00:05Z"))
    assert c.pre_decision_vendors == ()
    assert c.post_reject_vendors == ()