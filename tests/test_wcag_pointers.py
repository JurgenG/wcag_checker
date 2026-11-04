"""Tests for the manual-review pointer detections (:mod:`.wcag.pointers`).

Hermetic: the pure evaluator is driven with canned located-element data,
and :func:`check_pointers` with a fake driver whose ``execute_script``
returns a fixed payload. The in-page gatherer is validated live.

Note: 4.1.3 (status messages) and 2.4.5 (multiple ways) are *always-on* —
they fire whether or not their elements are found (a positive pointer when
present, an absence note when not). 3.3.8 and 3.2.6 only fire when their
elements exist. Tests therefore filter findings by criterion.
"""

from __future__ import annotations

from leak_inspector.wcag.core import Finding
from leak_inspector.wcag.pointers import check_pointers, evaluate_pointers


class _FakeDriver:
    def __init__(self, data: dict) -> None:
        self._data = data
        self.current_url = "https://x/current"

    def execute_script(self, script: str, *args) -> dict:
        return self._data


def _crits(findings: list[Finding]) -> set[str]:
    return {f.criterion for f in findings}


def _for(criterion: str, findings: list[Finding]) -> list[Finding]:
    return [f for f in findings if f.criterion == criterion]


class TestStatusMessages:
    def test_points_at_each_live_region(self) -> None:
        out = _for(
            "4.1.3",
            evaluate_pointers(
                {"live": [{"selector": "#toast", "role": "status", "ariaLive": "polite"}]},
                "u",
            ),
        )
        assert len(out) == 1
        assert out[0].severity == "needs-review"
        assert out[0].selector == "#toast"
        assert "status" in out[0].message

    def test_absence_is_flagged_without_a_selector(self) -> None:
        out = _for("4.1.3", evaluate_pointers({"live": []}, "u"))
        assert len(out) == 1
        assert out[0].selector is None
        assert "No ARIA live region" in out[0].message


class TestAuthentication:
    def test_password_field_points_at_login(self) -> None:
        out = _for("3.3.8", evaluate_pointers({"passwords": [{"selector": "#pass"}]}, "u"))
        assert len(out) == 1
        assert out[0].selector == "#pass"
        assert "password" in out[0].message.lower()

    def test_captcha_named_and_pointed_at(self) -> None:
        out = _for(
            "3.3.8",
            evaluate_pointers(
                {"captchas": [{"selector": ".g-recaptcha", "kind": "reCAPTCHA"}]}, "u"
            ),
        )
        assert len(out) == 1
        assert "reCAPTCHA" in out[0].message
        assert out[0].selector == ".g-recaptcha"

    def test_no_login_no_3_3_8(self) -> None:
        out = evaluate_pointers({"passwords": [], "captchas": []}, "u")
        assert "3.3.8" not in _crits(out)


class TestMultipleWays:
    def test_lists_detected_mechanisms_and_points_at_one(self) -> None:
        out = _for(
            "2.4.5",
            evaluate_pointers(
                {"search": [{"selector": "#q"}], "navs": [{"selector": "nav"}]}, "u"
            ),
        )
        assert len(out) == 1
        msg = out[0].message
        assert "search field" in msg and "site navigation" in msg
        assert "two or more" in msg  # two mechanisms → confirm they lead here
        assert out[0].selector == "#q"  # points at a concrete mechanism

    def test_single_mechanism_asks_for_one_more(self) -> None:
        out = _for("2.4.5", evaluate_pointers({"navs": [{"selector": "nav"}]}, "u"))
        assert "one more independent way" in out[0].message

    def test_none_detected_is_flagged(self) -> None:
        out = _for("2.4.5", evaluate_pointers({"search": [], "navs": [], "sitemap": []}, "u"))
        assert len(out) == 1
        assert out[0].selector is None
        assert "No obvious way to locate" in out[0].message


class TestConsistentHelp:
    def test_help_links_summarized_with_examples(self) -> None:
        out = _for(
            "3.2.6",
            evaluate_pointers(
                {
                    "help": [
                        {"selector": "a#c", "text": "Contact"},
                        {"selector": "a#s", "text": "Support"},
                    ]
                },
                "u",
            ),
        )
        assert len(out) == 1
        assert out[0].selector == "a#c"  # points at the first help mechanism
        assert "Contact" in out[0].message and "Support" in out[0].message

    def test_no_help_no_3_2_6(self) -> None:
        assert "3.2.6" not in _crits(evaluate_pointers({"help": []}, "u"))


class TestGeneral:
    def test_empty_page_yields_only_the_always_on_pointers(self) -> None:
        # No elements anywhere → 4.1.3 (no live region) and 2.4.5 (no way to
        # locate) still fire; 3.3.8 and 3.2.6 stay silent (nothing to check).
        assert _crits(evaluate_pointers({}, "u")) == {"2.4.5", "4.1.3"}

    def test_url_labels_findings(self) -> None:
        out = evaluate_pointers({"passwords": [{"selector": "#p"}]}, "https://x/a")
        assert all(f.url == "https://x/a" for f in out)


class TestCheckPointers:
    def test_runs_gatherer_and_evaluates(self) -> None:
        driver = _FakeDriver({"live": [{"selector": "#s", "role": "alert"}]})
        out = check_pointers(driver, "https://x/a")
        assert "4.1.3" in _crits(out)
        assert all(f.url == "https://x/a" for f in out)

    def test_url_defaults_to_current_url(self) -> None:
        driver = _FakeDriver({"passwords": [{"selector": "#p"}]})
        out = check_pointers(driver)
        assert _for("3.3.8", out)[0].url == "https://x/current"
