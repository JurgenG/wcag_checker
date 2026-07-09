"""Tests for item 4 of the verdict layer — the templated top verdict.

Three sentences (plus an optional fourth) above the technical
summary:

1. External-connection sentence: how many third-party vendors were
   contacted, and how many of them are classified as ``expected``.
2. Personal-data line (item 1).
3. Either the single highest-priority ``actionable`` vendor's note,
   or "Nothing requiring action was found." when none is actionable.
4. (conditional) "N vendor could not be classified." — appended when
   any contacted vendor's classification is ``unclassified``, so the
   verdict is honestly partial.
"""

from __future__ import annotations

from leak_inspector.report.verdict import (
    build_top_verdict_sentences,
    build_verdict,
)

from tests.fixtures.verdict import (
    analysis_empty,
    analysis_first_party_only,
    analysis_with_hits,
    analysis_with_personal_data,
    make_hit,
    make_param,
)
from leak_inspector.modules.base import CAT_IDENTIFIER, IMPACT_HIGH


# --- Builders for the four shapes we need to cover -------------------------


def _analysis_expected_only():
    """One vendor, classified as expected (gov_flanders)."""
    return analysis_with_hits(hits=[
        make_hit(
            module_id="gov_flanders",
            module_name="Flemish government (Vlaanderen)",
            host="widgets.vlaanderen.be",
        ),
    ])


def _analysis_with_actionable():
    """gov_flanders (expected) + google_fonts (actionable)."""
    return analysis_with_hits(hits=[
        make_hit(
            module_id="gov_flanders",
            module_name="Flemish government (Vlaanderen)",
            host="widgets.vlaanderen.be",
        ),
        make_hit(
            module_id="google_fonts",
            module_name="Google Fonts",
            host="fonts.googleapis.com",
        ),
    ])


def _analysis_with_unclassified():
    """One classified vendor + one untracked third-party host (azureedge-like)."""
    from leak_inspector.events import RequestEvent, TYPE_REQUEST
    a = analysis_with_hits(hits=[
        make_hit(
            module_id="gov_flanders",
            module_name="Flemish government (Vlaanderen)",
            host="widgets.vlaanderen.be",
        ),
    ])
    a.untracked_requests = [RequestEvent(
        event_id=99, timestamp="2026-05-30T00:00:01Z",
        type=TYPE_REQUEST, context_id=None, payload={},
        method="GET", url="https://something-unknown.azureedge.net/asset.css",
        host="something-unknown.azureedge.net",
        headers={}, request_body=None, initiator=None,
        response_status=200, response_mime="text/css",
        response_headers={},
    )]
    return a


# --- Sentence 1: external connections + expected count --------------------


def test_external_connection_sentence_counts_unique_vendors() -> None:
    sentences = build_top_verdict_sentences(_analysis_with_actionable())
    s1 = sentences[0]
    # 2 vendors contacted (gov_flanders + google_fonts), 1 of which is expected.
    assert "2" in s1
    assert "1" in s1
    assert "expected" in s1.lower()


def test_external_connection_sentence_counts_unclassified_hosts() -> None:
    """Untracked third-party hosts count as external vendors."""
    sentences = build_top_verdict_sentences(_analysis_with_unclassified())
    # 1 classified (gov_flanders) + 1 unclassified (azureedge) = 2 external vendors.
    assert sentences[0].startswith("The site contacted 2") or "2" in sentences[0]


def test_external_connection_sentence_handles_zero_vendors() -> None:
    """A capture that contacted nothing third-party."""
    s1 = build_top_verdict_sentences(analysis_empty())[0]
    assert "0" in s1 or "no" in s1.lower()


# --- Sentence 2: personal-data line (reuses item 1) -----------------------


def test_personal_data_sentence_is_item_one_output() -> None:
    sentences = build_top_verdict_sentences(_analysis_expected_only())
    assert sentences[1] == (
        "No citizen personal data was observed leaving the website "
        "during this scan."
    )


def test_personal_data_sentence_in_non_zero_case() -> None:
    sentences = build_top_verdict_sentences(analysis_with_personal_data())
    assert "personal-data field" in sentences[1].lower()


# --- Sentence 3: highest-priority actionable or fallback -----------------


def test_actionable_sentence_quotes_the_classifiers_note() -> None:
    sentences = build_top_verdict_sentences(_analysis_with_actionable())
    s3 = sentences[2]
    # The google_fonts note's content is reflected.
    assert "Google" in s3 or "font" in s3.lower()


def test_no_actionable_falls_back_to_canonical_line() -> None:
    """A site with only expected/strategic/unclassified vendors emits
    the canonical fallback."""
    sentences = build_top_verdict_sentences(_analysis_expected_only())
    assert sentences[2] == "Nothing requiring action was found."


def test_empty_capture_falls_back_to_canonical_line() -> None:
    sentences = build_top_verdict_sentences(analysis_empty())
    assert sentences[2] == "Nothing requiring action was found."


# --- Sentence 4: partial-coverage append (conditional) -------------------


def test_partial_coverage_append_fires_when_unclassified() -> None:
    sentences = build_top_verdict_sentences(_analysis_with_unclassified())
    # The unclassified azureedge host triggers the 4th sentence.
    assert len(sentences) == 4
    assert "could not be classified" in sentences[3]
    assert "1" in sentences[3]


def test_partial_coverage_append_omitted_when_all_classified() -> None:
    """All vendors map to known categories → no partial append."""
    sentences = build_top_verdict_sentences(_analysis_with_actionable())
    assert len(sentences) == 3


def test_first_party_hits_do_not_count_as_unclassified() -> None:
    """A first-party host with no module shouldn't trip the partial append."""
    sentences = build_top_verdict_sentences(analysis_first_party_only())
    # No partial-coverage sentence — the first-party hit isn't a vendor.
    assert len(sentences) == 3


# --- Integration with build_verdict + Verdict object --------------------


def test_verdict_carries_top_sentences() -> None:
    """``build_verdict`` returns a Verdict whose ``top_sentences`` is the
    same list ``build_top_verdict_sentences`` would produce standalone."""
    a = _analysis_with_actionable()
    v = build_verdict(a)
    assert v.top_sentences == build_top_verdict_sentences(a)
