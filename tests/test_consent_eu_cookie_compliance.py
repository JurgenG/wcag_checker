"""Decode EU Cookie Compliance's ``cookie-agreed`` decision cookie.

The Drupal module stores the visitor's choice in a first-party
``cookie-agreed`` cookie: ``0`` = declined, a non-zero value
(``1``/``2``) = agreed. (The agreed category names live in a separate
``cookie-agreed-categories`` cookie; the decision state itself is
fully determined by ``cookie-agreed``, so the decoder keys on that.)
Absent cookie = no decision — the caller's conclusion, not ours.
"""

from __future__ import annotations

from leak_inspector.analysis.consent import (
    CONSENT_COOKIE_NAMES,
    decode_consent_artifact,
)


def test_cookie_name_is_recognised() -> None:
    assert "cookie-agreed" in CONSENT_COOKIE_NAMES


def test_declined_decodes_to_rejected() -> None:
    d = decode_consent_artifact("cookie-agreed", "0")
    assert d is not None
    assert d.state == "rejected"
    assert d.source == "eu_cookie_compliance"


def test_agreed_decodes_to_accepted() -> None:
    for value in ("1", "2"):
        d = decode_consent_artifact("cookie-agreed", value)
        assert d is not None, value
        assert d.state == "accepted", value
        assert d.source == "eu_cookie_compliance"


def test_unparseable_value_is_none() -> None:
    # Not a decision integer → never guess.
    assert decode_consent_artifact("cookie-agreed", "") is None
    assert decode_consent_artifact("cookie-agreed", "yes") is None


def test_url_encoded_value_round_trips() -> None:
    # Cookie values arrive URL-encoded from the bundle; "2" stays "2".
    d = decode_consent_artifact("cookie-agreed", "2")
    assert d is not None and d.state == "accepted"
