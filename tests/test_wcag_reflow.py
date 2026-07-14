"""Tests for the 320px reflow check (:mod:`.wcag.reflow`).

Hermetic: the pure evaluator is driven with canned measurements, and
:func:`check_reflow` with a fake driver that mimics the BiDi
``browsing_context.set_viewport`` seam (recording calls so the
save/restore round-trip is verified) — no browser. The live viewport
resize is validated against a fixture separately.
"""

from __future__ import annotations

from leak_inspector.wcag.reflow import REFLOW_WIDTH, check_reflow, evaluate_reflow


class TestEvaluateReflow:
    def test_horizontal_overflow_is_flagged(self) -> None:
        out = evaluate_reflow({"scroll_width": 900, "client_width": 320}, "u")
        assert len(out) == 1
        assert out[0].criterion == "1.4.10"
        assert out[0].severity == "needs-review"
        assert out[0].selector is None  # page-level finding

    def test_no_overflow_yields_nothing(self) -> None:
        assert evaluate_reflow({"scroll_width": 320, "client_width": 320}, "u") == []

    def test_one_pixel_rounding_is_tolerated(self) -> None:
        assert evaluate_reflow({"scroll_width": 321, "client_width": 320}, "u") == []

    def test_beyond_tolerance_is_flagged(self) -> None:
        assert evaluate_reflow({"scroll_width": 323, "client_width": 320}, "u")


class _FakeBrowsingContext:
    def __init__(self) -> None:
        self.calls: list[dict] = []

    def set_viewport(self, *, context, viewport, **kwargs) -> None:
        self.calls.append(viewport)


class _FakeDriver:
    def __init__(self, scroll_width: int, inner: int = 1366) -> None:
        self._scroll_width = scroll_width
        self._inner = inner
        self.current_url = "https://x/current"
        self.current_window_handle = "ctx-1"
        self.browsing_context = _FakeBrowsingContext()

    def execute_script(self, script: str, *args):
        if "innerWidth" in script and "scrollWidth" not in script:
            return {"w": self._inner, "h": 900}
        if "scrollWidth" in script:
            # After the viewport was set to REFLOW_WIDTH.
            return {"scrollWidth": self._scroll_width, "clientWidth": REFLOW_WIDTH}
        return None


class TestCheckReflow:
    def test_flags_overflow_at_320(self) -> None:
        driver = _FakeDriver(scroll_width=900)
        out = check_reflow(driver, "https://x/a")
        assert [f.criterion for f in out] == ["1.4.10"]

    def test_no_finding_when_page_fits(self) -> None:
        assert check_reflow(_FakeDriver(scroll_width=320), "https://x/a") == []

    def test_sets_320_then_restores_original_viewport(self) -> None:
        driver = _FakeDriver(scroll_width=900, inner=1280)
        check_reflow(driver, "https://x/a")
        widths = [v["width"] for v in driver.browsing_context.calls]
        assert widths == [REFLOW_WIDTH, 1280]  # measured at 320, then restored

    def test_returns_empty_when_bidi_unavailable(self) -> None:
        class _NoBidi:
            current_url = "u"
            current_window_handle = "c"

            def execute_script(self, script, *args):
                return {"w": 1000, "h": 800}

            # accessing .browsing_context raises AttributeError

        assert check_reflow(_NoBidi(), "u") == []

    def test_url_defaults_to_current_url(self) -> None:
        driver = _FakeDriver(scroll_width=900)
        assert check_reflow(driver)[0].url == "https://x/current"
