"""Tests for the consent-artifact decoders (Phase 1 of consent-state
detection).

Every positive test value below is lifted verbatim from a real
capture: Cookiebot from ``doccle-reject.zip`` / ``doccle-accept.zip``,
Cookie Script from ``cultuurkuur.zip``, OneTrust from
``captures/colruyt-max.zip``. No synthetic consent payloads — the
decoders are only trusted to handle what CMPs actually write.
"""

from __future__ import annotations

import pytest

from leak_inspector.analysis.consent import (
    ConsentDecision,
    decode_consent_artifact,
)


# --- real artifact values ----------------------------------------------------

# doccle.be, Cookiebot, user clicked reject (doccle-reject.zip).
COOKIEBOT_REJECT = (
    "{stamp:'Tx6T1N0CfYLsUF3LID37qKtwlAGM9rw/MImOFr0U5LqEnLlqfc0Ddw==',"
    "necessary:true,preferences:false,statistics:false,marketing:false,"
    "method:'explicit',ver:1,utc:1780155987483,region:'be'}"
)

# doccle.be, Cookiebot, user clicked accept-all (doccle-accept.zip).
COOKIEBOT_ACCEPT = (
    "{stamp:'7d5kioiRKtOTLUxdYY2ftU/zkDoQDFd4tjNedGdGnn0M17AIGJayMQ==',"
    "necessary:true,preferences:true,statistics:true,marketing:true,"
    "method:'explicit',ver:1,utc:1780155568446,region:'be'}"
)

# The URL-encoded form exactly as it sits in the bundle's cookie jar.
COOKIEBOT_REJECT_ENCODED = COOKIEBOT_REJECT.replace("'", "%27").replace(
    ",", "%2C"
)

# www.cultuurkuur.be, Cookie Script, user clicked reject
# (cultuurkuur.zip). ``categories`` is a JSON-encoded *string*.
COOKIE_SCRIPT_REJECT = (
    '{"bannershown":1,"action":"reject","consenttime":1748421407,'
    '"categories":"[]","key":"1900c11e-2d80-455e-b1e8-a458cc0bb1f3"}'
)

# www.colruyt.be, OneTrust, user accepted all groups (colruyt-max.zip).
ONETRUST_ACCEPT = (
    "isGpcEnabled=0&datestamp=Fri+May+29+2026+20:56:22+GMT+0200+"
    "(Central+European+Summer+Time)&version=202402.1.0&browserGpcFlag=0&"
    "isIABGlobal=false&hosts=&consentId=3149b7d9-1b19-4989-a723-34c981881f11&"
    "interactionCount=1&isAnonUser=1&landingPath=NotLandingPage&"
    "groups=C0001:1,C0003:1,C0002:1,C0004:1"
)

# Derived reject variant: same shape, all non-essential groups 0.
# (No real all-reject OneTrust capture yet; the groups grammar is
# identical, only the flag values differ.)
ONETRUST_REJECT = ONETRUST_ACCEPT.replace(
    "groups=C0001:1,C0003:1,C0002:1,C0004:1",
    "groups=C0001:1,C0003:0,C0002:0,C0004:0",
)


# --- Cookiebot ---------------------------------------------------------------


def test_cookiebot_reject() -> None:
    d = decode_consent_artifact("CookieConsent", COOKIEBOT_REJECT)
    assert isinstance(d, ConsentDecision)
    assert d.state == "rejected"
    assert d.source == "cookiebot"
    assert d.granted == ()


def test_cookiebot_accept_all() -> None:
    d = decode_consent_artifact("CookieConsent", COOKIEBOT_ACCEPT)
    assert d.state == "accepted"
    assert d.granted == ("marketing", "preferences", "statistics")


def test_cookiebot_partial_is_accepted() -> None:
    """Any non-essential category granted → state 3 (accept more)."""
    partial = COOKIEBOT_ACCEPT.replace(
        "statistics:true", "statistics:false"
    ).replace("marketing:true", "marketing:false")
    d = decode_consent_artifact("CookieConsent", partial)
    assert d.state == "accepted"
    assert d.granted == ("preferences",)


def test_cookiebot_url_encoded_form() -> None:
    """The bundle stores the cookie value URL-encoded; the decoder
    must handle that form directly."""
    d = decode_consent_artifact("CookieConsent", COOKIEBOT_REJECT_ENCODED)
    assert d is not None
    assert d.state == "rejected"


# --- Cookie Script -----------------------------------------------------------


def test_cookie_script_reject() -> None:
    d = decode_consent_artifact("CookieScriptConsent", COOKIE_SCRIPT_REJECT)
    assert d.state == "rejected"
    assert d.source == "cookie_script"
    assert d.granted == ()


def test_cookie_script_accept_with_categories() -> None:
    accept = COOKIE_SCRIPT_REJECT.replace(
        '"action":"reject"', '"action":"accept"'
    ).replace('"categories":"[]"', '"categories":"[\\"targeting\\"]"')
    d = decode_consent_artifact("CookieScriptConsent", accept)
    assert d.state == "accepted"
    assert d.granted == ("targeting",)


# --- OneTrust ----------------------------------------------------------------


def test_onetrust_accept_all() -> None:
    d = decode_consent_artifact("OptanonConsent", ONETRUST_ACCEPT)
    assert d.state == "accepted"
    assert d.source == "onetrust"
    # C0001 (strictly necessary) is not a *granted* consent.
    assert d.granted == ("C0002", "C0003", "C0004")


def test_onetrust_reject_all_non_essential() -> None:
    d = decode_consent_artifact("OptanonConsent", ONETRUST_REJECT)
    assert d.state == "rejected"
    assert d.granted == ()


# --- dispatch / robustness ---------------------------------------------------


def test_unknown_cookie_name_returns_none() -> None:
    assert decode_consent_artifact("session_id", "whatever") is None


def test_malformed_values_return_none() -> None:
    for name in ("CookieConsent", "CookieScriptConsent", "OptanonConsent"):
        assert decode_consent_artifact(name, "") is None
        assert decode_consent_artifact(name, "garbage") is None


def test_decision_keeps_raw_value() -> None:
    d = decode_consent_artifact("CookieScriptConsent", COOKIE_SCRIPT_REJECT)
    assert d.raw == COOKIE_SCRIPT_REJECT
