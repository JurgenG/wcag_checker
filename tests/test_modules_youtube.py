"""Tests for the YouTube embed module."""

from __future__ import annotations

import json

import pytest

from leak_inspector.modules.base import (
    CAT_BEHAVIORAL,
    CAT_CONSENT,
    CAT_CONTENT,
    CAT_IDENTIFIER,
    CAT_OTHER,
    CAT_PII,
    CAT_TECHNICAL,
    IMPACT_HIGH,
)

from tests.conftest import make_request, module_by_id


@pytest.fixture
def yt():
    return module_by_id("youtube")


def test_identity(yt) -> None:
    assert yt.module_id == "youtube"


@pytest.mark.parametrize(
    "host",
    [
        "youtube.com", "www.youtube.com", "youtube-nocookie.com",
        "i.ytimg.com", "googlevideo.com", "rr5---sn-foo.googlevideo.com",
        "jnn-pa.googleapis.com",
    ],
)
def test_matches(yt, host: str) -> None:
    event = make_request(host=host, url=f"https://{host}/x")
    assert yt.matches(event) is True


def test_matches_yt_prefixed_ggpht(yt) -> None:
    event = make_request(host="yt3.ggpht.com", url="https://yt3.ggpht.com/avatar.jpg")
    assert yt.matches(event) is True


def test_does_not_match_other_ggpht(yt) -> None:
    """Photos / Workspace avatars on ``lh*.ggpht.com`` are NOT YouTube."""
    event = make_request(host="lh3.ggpht.com", url="https://lh3.ggpht.com/x")
    assert yt.matches(event) is False


def test_does_not_match_unrelated(yt) -> None:
    event = make_request(host="example.com", url="https://example.com/")
    assert yt.matches(event) is False


@pytest.mark.parametrize("key", ["v", "docid", "list", "video_id"])
def test_video_ids_are_content(yt, key: str) -> None:
    event = make_request(host="www.youtube.com", url=f"https://www.youtube.com/watch?{key}=ABCDEF")
    hit = yt.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_CONTENT


@pytest.mark.parametrize("key", ["cpn", "ei", "vid", "plid", "session_token"])
def test_playback_identifiers(yt, key: str) -> None:
    event = make_request(host="www.youtube.com", url=f"https://www.youtube.com/api/stats/x?{key}=ABC")
    hit = yt.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_IDENTIFIER


@pytest.mark.parametrize("key", ["embed_domain", "widget_referrer", "origin", "forigin", "euri"])
def test_embed_context_content(yt, key: str) -> None:
    event = make_request(host="www.youtube.com", url=f"https://www.youtube.com/embed/abc?{key}=x")
    hit = yt.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_CONTENT


def test_googlevideo_ip_is_pii_high(yt) -> None:
    """``ip`` on signed googlevideo URLs is the visitor's IP baked into the URL."""
    event = make_request(
        host="rr1.googlevideo.com",
        url="https://rr1.googlevideo.com/videoplayback?ip=1.2.3.4",
    )
    hit = yt.parse(event)
    p = next(p for p in hit.params if p.key == "ip")
    assert p.category == CAT_PII
    assert p.privacy_impact == IMPACT_HIGH


def test_skip_keys_filtered_out(yt) -> None:
    """Player UI / CDN streaming internals are filtered before ParamInfo emission."""
    event = make_request(
        host="www.youtube.com",
        url="https://www.youtube.com/embed/abc?controls=0&iv_load_policy=3&modestbranding=1&v=XYZ",
    )
    hit = yt.parse(event)
    keys = [p.key for p in hit.params]
    # Skipped:
    assert "controls" not in keys
    assert "iv_load_policy" not in keys
    assert "modestbranding" not in keys
    # Kept (video ID is real content):
    assert "v" in keys


def test_youtubei_body_extracts_client_and_visitor_data(yt) -> None:
    """``/youtubei/v1/log_event`` bodies carry ``context.client`` + ``events``."""
    body = json.dumps({
        "context": {
            "client": {
                "clientName": "WEB_EMBEDDED_PLAYER",
                "clientVersion": "1.20260101.00.00",
                "hl": "en",
                "gl": "US",
                "visitorData": "VISITOR-TOKEN",
            },
        },
        "events": [{"interactionLoggingPayload": "x"}, {"interactionLoggingPayload": "y"}],
    })
    event = make_request(
        host="www.youtube.com",
        url="https://www.youtube.com/youtubei/v1/log_event?prettyPrint=false",
        method="POST",
        request_body=body,
    )
    hit = yt.parse(event)
    by_key = {p.key: p for p in hit.params}
    assert by_key["(body) client_name"].value == "WEB_EMBEDDED_PLAYER"
    assert by_key["(body) language"].value == "en"
    assert by_key["(body) visitor_data"].category == CAT_IDENTIFIER
    assert by_key["(body) visitor_data"].privacy_impact == IMPACT_HIGH
    assert by_key["(body) logged_event_count"].value == "2"


def test_youtubei_body_skipped_for_non_youtubei_path(yt) -> None:
    """The body parser only runs for ``/youtubei/v1/`` paths."""
    body = json.dumps({"context": {"client": {"clientName": "WEB"}}})
    event = make_request(
        host="www.youtube.com",
        url="https://www.youtube.com/watch?v=abc",
        method="POST",
        request_body=body,
    )
    hit = yt.parse(event)
    assert not any(p.key == "(body) client_name" for p in hit.params)


def test_youtubei_body_handles_invalid_json(yt) -> None:
    event = make_request(
        host="www.youtube.com",
        url="https://www.youtube.com/youtubei/v1/log_event",
        request_body="not-json",
    )
    hit = yt.parse(event)
    assert not any(p.key.startswith("(body)") for p in hit.params)


def test_unknown_param(yt) -> None:
    event = make_request(host="www.youtube.com", url="https://www.youtube.com/?weirdo=1")
    hit = yt.parse(event)
    p = next(p for p in hit.params if p.key == "weirdo")
    assert p.category == CAT_OTHER
    assert "YouTube" in p.meaning
