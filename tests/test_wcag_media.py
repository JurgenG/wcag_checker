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


def _video(selector: str = "video#v", tracks: list[dict] | None = None) -> dict:
    return {"type": "media", "tag": "video", "selector": selector, "tracks": tracks or []}


def _audio(selector: str = "audio#a", tracks: list[dict] | None = None) -> dict:
    return {"type": "media", "tag": "audio", "selector": selector, "tracks": tracks or []}


def _iframe(src: str, *, selector: str = "iframe", title: str = "") -> dict:
    return {"type": "iframe", "selector": selector, "src": src, "title": title}


class TestNativeMedia:
    def test_audio_yields_a_1_2_1_transcript_candidate(self) -> None:
        out = evaluate_media([_audio("audio#a")], "u")
        assert len(out) == 1
        assert out[0].criterion == "1.2.1"
        assert out[0].severity == "needs-review"
        assert out[0].selector == "audio#a"
        assert "transcript" in out[0].message.lower()

    def test_audio_reports_declared_tracks(self) -> None:
        out = evaluate_media([_audio(tracks=[{"kind": "descriptions"}])], "u")
        assert "descriptions" in out[0].message

    def test_video_states_no_tracks_when_none(self) -> None:
        out = evaluate_media([_video()], "u")
        assert [f.criterion for f in out] == ["1.2.3"]
        msg = out[0].message
        assert "captions: no" in msg and "subtitles: no" in msg and "descriptions: no" in msg

    def test_video_states_captions_and_subtitles_found(self) -> None:
        out = evaluate_media(
            [_video(tracks=[{"kind": "captions"}, {"kind": "subtitles"}])], "u"
        )
        msg = out[0].message
        assert "captions: yes" in msg
        assert "subtitles: yes" in msg
        assert "descriptions: no" in msg

    def test_mixed_media_yields_both(self) -> None:
        out = evaluate_media([_video(selector="v"), _audio(selector="a")], "u")
        assert {f.criterion for f in out} == {"1.2.1", "1.2.3"}

    def test_legacy_record_without_type_still_classified(self) -> None:
        # Older inventory shape (no ``type``/``tracks``) still maps by tag.
        out = evaluate_media([{"tag": "video", "selector": "v"}], "u")
        assert [f.criterion for f in out] == ["1.2.3"]


class TestEmbeds:
    def test_youtube_embed_flags_captions_and_description_as_unauditable(self) -> None:
        out = evaluate_media([_iframe("https://www.youtube.com/embed/abc123")], "u")
        assert [f.criterion for f in out] == ["1.2.2", "1.2.3"]
        for f in out:
            assert f.severity == "needs-review"
            assert "YouTube" in f.message
            assert "cannot be inspected" in f.message
            assert f.selector == "iframe"

    def test_vimeo_embed_recognized(self) -> None:
        out = evaluate_media([_iframe("https://player.vimeo.com/video/123")], "u")
        assert [f.criterion for f in out] == ["1.2.2", "1.2.3"]
        assert all("Vimeo" in f.message for f in out)

    def test_youtube_short_and_nocookie_hosts_recognized(self) -> None:
        for src in (
            "https://youtu.be/abc",
            "https://www.youtube-nocookie.com/embed/abc",
        ):
            out = evaluate_media([_iframe(src)], "u")
            assert [f.criterion for f in out] == ["1.2.2", "1.2.3"]
            assert all("YouTube" in f.message for f in out)

    def test_other_iframe_flagged_for_manual_review_under_1_2_1(self) -> None:
        out = evaluate_media([_iframe("https://maps.example.com/x", title="Map")], "u")
        assert [f.criterion for f in out] == ["1.2.1"]
        msg = out[0].message
        assert "could not be audited" in msg
        assert "maps.example.com" in msg
        assert "Map" in msg  # title surfaced for the reviewer
        assert "N/A" in msg

    def test_iframe_without_src_is_still_flagged(self) -> None:
        out = evaluate_media([_iframe("", selector="iframe#f")], "u")
        assert [f.criterion for f in out] == ["1.2.1"]
        assert "no external src" in out[0].message
        assert out[0].selector == "iframe#f"


class TestGeneral:
    def test_no_media_yields_nothing(self) -> None:
        assert evaluate_media([], "u") == []

    def test_unknown_tag_ignored(self) -> None:
        assert evaluate_media([{"type": "media", "tag": "object", "selector": "o"}], "u") == []

    def test_url_labels_findings(self) -> None:
        out = evaluate_media([_audio()], "https://x/a")
        assert out[0].url == "https://x/a"


class TestCheckMedia:
    def test_runs_gatherer_and_evaluates(self) -> None:
        driver = _FakeDriver([_video(selector="v")])
        out = check_media(driver, "https://x/a")
        assert [f.criterion for f in out] == ["1.2.3"]

    def test_url_defaults_to_current_url(self) -> None:
        driver = _FakeDriver([_audio()])
        assert check_media(driver)[0].url == "https://x/current"

    def test_iframe_inventory_flows_through(self) -> None:
        driver = _FakeDriver([_iframe("https://www.youtube.com/embed/x")])
        out = check_media(driver, "https://x/a")
        assert [f.criterion for f in out] == ["1.2.2", "1.2.3"]