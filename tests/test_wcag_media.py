"""Tests for the time-based-media presence checks (:mod:`.wcag.media`).

Hermetic: the pure evaluator is driven with canned inventory records, and
:func:`check_media` with a fake driver whose ``execute_script`` returns a
fixed payload. The in-page gatherer is validated live against a fixture.
"""

from __future__ import annotations

from leak_inspector.wcag.media import check_media, evaluate_media


class _FakeDriver:
    def __init__(self, records: list[dict]) -> None:
        self._records = records
        self.current_url = "https://x/current"

    def execute_script(self, script: str, *args) -> list[dict]:
        return self._records


class TestEvaluateMedia:
    def test_audio_yields_a_1_2_1_transcript_candidate(self) -> None:
        out = evaluate_media([{"tag": "audio", "selector": "audio#a"}], "u")
        assert len(out) == 1
        assert out[0].criterion == "1.2.1"
        assert out[0].severity == "needs-review"
        assert out[0].selector == "audio#a"

    def test_video_yields_a_1_2_3_description_candidate(self) -> None:
        out = evaluate_media([{"tag": "video", "selector": "video#v"}], "u")
        assert [f.criterion for f in out] == ["1.2.3"]
        assert out[0].severity == "needs-review"

    def test_mixed_media_yields_both(self) -> None:
        out = evaluate_media(
            [{"tag": "video", "selector": "v"}, {"tag": "audio", "selector": "a"}],
            "u",
        )
        assert {f.criterion for f in out} == {"1.2.1", "1.2.3"}

    def test_no_media_yields_nothing(self) -> None:
        assert evaluate_media([], "u") == []

    def test_unknown_tag_ignored(self) -> None:
        assert evaluate_media([{"tag": "object", "selector": "o"}], "u") == []

    def test_url_labels_findings(self) -> None:
        out = evaluate_media([{"tag": "audio", "selector": "a"}], "https://x/a")
        assert out[0].url == "https://x/a"


class TestCheckMedia:
    def test_runs_gatherer_and_evaluates(self) -> None:
        driver = _FakeDriver([{"tag": "video", "selector": "v"}])
        out = check_media(driver, "https://x/a")
        assert [f.criterion for f in out] == ["1.2.3"]

    def test_url_defaults_to_current_url(self) -> None:
        driver = _FakeDriver([{"tag": "audio", "selector": "a"}])
        assert check_media(driver)[0].url == "https://x/current"
