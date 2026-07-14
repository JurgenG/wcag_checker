"""Tests for the descriptive-text heuristics (:mod:`.wcag.content`).

Hermetic: the pure evaluators are driven with canned records, and the
``check_*`` gatherers with a fake driver returning a fixed payload. The
in-page gatherers are validated live against a fixture.
"""

from __future__ import annotations

from leak_inspector.wcag.content import (
    VAGUE_LINK_PHRASES,
    check_empty_headings,
    check_link_purpose,
    evaluate_empty_headings,
    evaluate_link_purpose,
    run_all,
)


class _FakeDriver:
    def __init__(self, records: list[dict]) -> None:
        self._records = records
        self.current_url = "https://x/current"

    def execute_script(self, script: str, *args) -> list[dict]:
        return self._records


class TestEvaluateLinkPurpose:
    def test_generic_text_is_flagged(self) -> None:
        out = evaluate_link_purpose([{"name": "click here", "selector": "a#1"}], "u")
        assert [f.criterion for f in out] == ["2.4.4"]
        assert out[0].severity == "needs-review"
        assert out[0].selector == "a#1"

    def test_decorated_generic_text_is_normalised_and_flagged(self) -> None:
        # Punctuation / arrows / case do not save a filler phrase.
        for name in ("Read more »", "READ MORE", "read more!", "  More  "):
            out = evaluate_link_purpose([{"name": name, "selector": "a"}], "u")
            assert len(out) == 1, name

    def test_descriptive_text_is_not_flagged(self) -> None:
        out = evaluate_link_purpose(
            [{"name": "Download the 2026 annual report (PDF)", "selector": "a"}], "u"
        )
        assert out == []

    def test_empty_name_left_to_axe(self) -> None:
        assert evaluate_link_purpose([{"name": "", "selector": "a"}], "u") == []

    def test_message_quotes_original_text(self) -> None:
        out = evaluate_link_purpose([{"name": "Read more »", "selector": "a"}], "u")
        assert "'Read more »'" in out[0].message  # original, not normalised

    def test_every_listed_phrase_matches(self) -> None:
        for phrase in VAGUE_LINK_PHRASES:
            out = evaluate_link_purpose([{"name": phrase, "selector": "a"}], "u")
            assert len(out) == 1, phrase


class TestEvaluateEmptyHeadings:
    def test_empty_heading_flagged(self) -> None:
        out = evaluate_empty_headings([{"empty": True, "selector": "h2"}], "u")
        assert [f.criterion for f in out] == ["2.4.6"]
        assert out[0].severity == "needs-review"

    def test_non_empty_heading_not_flagged(self) -> None:
        assert evaluate_empty_headings([{"empty": False, "selector": "h1"}], "u") == []

    def test_multiple(self) -> None:
        out = evaluate_empty_headings(
            [{"empty": True, "selector": "h2"}, {"empty": False, "selector": "h3"}],
            "u",
        )
        assert len(out) == 1


class TestCheckGatherers:
    def test_check_link_purpose_runs_and_evaluates(self) -> None:
        driver = _FakeDriver([{"name": "click here", "selector": "a"}])
        assert [f.criterion for f in check_link_purpose(driver, "u")] == ["2.4.4"]

    def test_check_empty_headings_runs_and_evaluates(self) -> None:
        driver = _FakeDriver([{"empty": True, "selector": "h2"}])
        assert [f.criterion for f in check_empty_headings(driver, "u")] == ["2.4.6"]

    def test_url_defaults_to_current_url(self) -> None:
        driver = _FakeDriver([{"name": "here", "selector": "a"}])
        assert check_link_purpose(driver)[0].url == "https://x/current"

    def test_run_all_combines_both(self, monkeypatch) -> None:
        from leak_inspector.wcag import content

        monkeypatch.setattr(
            content, "check_link_purpose", lambda d, u: [object()]
        )
        monkeypatch.setattr(
            content, "check_empty_headings", lambda d, u: [object(), object()]
        )
        assert len(run_all(_FakeDriver([]), "u")) == 3
