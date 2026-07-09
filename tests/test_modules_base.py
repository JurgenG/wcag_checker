"""Tests for ``leak_inspector.modules.base`` — the tracker module framework.

The 21 spec rules confirmed before deleting the implementation:

* Rules 1-3: category and impact string constants, CATEGORIES tuple order.
* Rules 4-6: ParamInfo / Hit dataclass shape and per-instance defaults.
* Rules 7-9: TrackerModule class-level attrs and NotImplementedError stubs.
* Rules 10-21: registry singleton + register / all_modules / detect /
  reset_registry.
"""

from __future__ import annotations

import pytest

from leak_inspector.modules.base import (
    CAT_BEHAVIORAL,
    CAT_CONSENT,
    CAT_CONTENT,
    CAT_HTTP_TRAFFIC,
    CAT_IDENTIFIER,
    CAT_OTHER,
    CAT_PII,
    CAT_TECHNICAL,
    CATEGORIES,
    Hit,
    IMPACT_HIGH,
    IMPACT_LOW,
    IMPACT_MEDIUM,
    ParamInfo,
    TrackerModule,
    all_modules,
    detect,
    register,
    reset_registry,
)


# --- fixtures ---------------------------------------------------------------


@pytest.fixture(autouse=True)
def _clean_registry():
    """Run each test on an empty registry, then restore the original state.

    Tracker modules self-register at import time via ``@register``. Once the
    process has imported ``leak_inspector.modules``, that registration data
    is the only copy — clearing the registry without restoring would break
    every test file that runs after this one.
    """
    from leak_inspector.modules import base as _base
    snapshot = list(_base._REGISTRY)
    _base._REGISTRY.clear()
    try:
        yield
    finally:
        _base._REGISTRY.clear()
        _base._REGISTRY.extend(snapshot)


def _make_module(
    module_id: str, *, matches_result: bool = False
) -> type[TrackerModule]:
    """Build a TrackerModule subclass with a controllable ``matches``."""

    class _Mod(TrackerModule):
        pass

    _Mod.module_id = module_id
    _Mod.module_name = module_id.title()
    _Mod.matches = lambda self, event: matches_result  # type: ignore[assignment]
    _Mod.parse = lambda self, event: Hit(  # type: ignore[assignment]
        module_id=module_id,
        module_name=module_id.title(),
        url="https://example.com/",
        host="example.com",
        method="GET",
        response_status=None,
        started_at="",
    )
    return _Mod


# --- category constants (rules 1-2) -----------------------------------------


@pytest.mark.parametrize(
    ("constant", "expected"),
    [
        (CAT_PII, "pii"),
        (CAT_IDENTIFIER, "identifier"),
        (CAT_BEHAVIORAL, "behavioral"),
        (CAT_HTTP_TRAFFIC, "http_traffic"),
        (CAT_TECHNICAL, "technical"),
        (CAT_CONSENT, "consent"),
        (CAT_CONTENT, "content"),
        (CAT_OTHER, "other"),
    ],
)
def test_category_constant_values(constant: str, expected: str) -> None:
    assert constant == expected


def test_categories_is_tuple_in_canonical_order() -> None:
    assert isinstance(CATEGORIES, tuple)
    assert CATEGORIES == (
        CAT_PII,
        CAT_IDENTIFIER,
        CAT_BEHAVIORAL,
        CAT_HTTP_TRAFFIC,
        CAT_CONSENT,
        CAT_CONTENT,
        CAT_TECHNICAL,
        CAT_OTHER,
    )


# --- impact constants (rule 3) ----------------------------------------------


@pytest.mark.parametrize(
    ("constant", "expected"),
    [
        (IMPACT_HIGH, "high"),
        (IMPACT_MEDIUM, "medium"),
        (IMPACT_LOW, "low"),
    ],
)
def test_impact_constant_values(constant: str, expected: str) -> None:
    assert constant == expected


# --- ParamInfo (rule 4) -----------------------------------------------------


def test_param_info_required_positional_fields() -> None:
    p = ParamInfo("utm_source", "google", CAT_BEHAVIORAL, "campaign", IMPACT_LOW, 0)
    assert p.key == "utm_source"
    assert p.value == "google"
    assert p.category == CAT_BEHAVIORAL
    assert p.meaning == "campaign"
    assert p.privacy_impact == IMPACT_LOW
    assert p.event_index == 0


def test_param_info_is_mutable() -> None:
    p = ParamInfo("k", "v", CAT_OTHER, "m", IMPACT_LOW, 0)
    p.value = "v2"
    assert p.value == "v2"


# --- Hit (rules 5-6) --------------------------------------------------------


def test_hit_required_positional_fields() -> None:
    h = Hit(
        module_id="ga4",
        module_name="GA4",
        url="https://google-analytics.com/g/collect",
        host="google-analytics.com",
        method="POST",
        response_status=200,
        started_at="2026-05-01T12:00:00Z",
    )
    assert h.module_id == "ga4"
    assert h.module_name == "GA4"
    assert h.url == "https://google-analytics.com/g/collect"
    assert h.host == "google-analytics.com"
    assert h.method == "POST"
    assert h.response_status == 200
    assert h.started_at == "2026-05-01T12:00:00Z"


def test_hit_optional_fields_default_correctly() -> None:
    h = Hit(
        module_id="m",
        module_name="M",
        url="",
        host="",
        method="GET",
        response_status=None,
        started_at="",
    )
    assert h.params == []
    assert h.events == []
    assert h.request_body is None
    assert h.response_body is None


def test_hit_default_lists_are_per_instance() -> None:
    h1 = Hit(
        module_id="a", module_name="A", url="", host="", method="GET",
        response_status=None, started_at="",
    )
    h2 = Hit(
        module_id="b", module_name="B", url="", host="", method="GET",
        response_status=None, started_at="",
    )
    h1.params.append(ParamInfo("k", "v", CAT_OTHER, "", IMPACT_LOW, 0))
    h1.events.append(99)
    assert h2.params == []
    assert h2.events == []


# --- TrackerModule (rules 7-9) ----------------------------------------------


def test_tracker_module_class_attrs_default_to_empty_string() -> None:
    assert TrackerModule.module_id == ""
    assert TrackerModule.module_name == ""
    assert TrackerModule.vendor == ""
    assert TrackerModule.legal_jurisdiction == ""
    assert TrackerModule.data_residency == ""
    assert TrackerModule.sovereignty_notes == ""


def test_tracker_module_matches_raises_not_implemented() -> None:
    with pytest.raises(NotImplementedError):
        TrackerModule().matches(object())  # type: ignore[arg-type]


def test_tracker_module_parse_raises_not_implemented() -> None:
    with pytest.raises(NotImplementedError):
        TrackerModule().parse(object())  # type: ignore[arg-type]


# --- register (rules 11-15) -------------------------------------------------


def test_register_returns_class_unchanged() -> None:
    mod = _make_module("m1")
    assert register(mod) is mod


def test_register_instantiates_and_stores_instance() -> None:
    mod = _make_module("m1")
    register(mod)
    registered = all_modules()
    assert len(registered) == 1
    assert isinstance(registered[0], mod)


def test_register_rejects_empty_module_id() -> None:
    class Bad(TrackerModule):
        pass

    with pytest.raises(ValueError):
        register(Bad)


def test_register_rejects_duplicate_module_id() -> None:
    register(_make_module("dup"))
    with pytest.raises(ValueError):
        register(_make_module("dup"))


def test_register_failure_does_not_mutate_registry() -> None:
    register(_make_module("a"))
    snapshot = all_modules()
    with pytest.raises(ValueError):
        register(_make_module("a"))  # duplicate
    assert all_modules() == snapshot


# --- all_modules (rules 16-17) ----------------------------------------------


def test_all_modules_preserves_registration_order() -> None:
    register(_make_module("first"))
    register(_make_module("second"))
    register(_make_module("third"))
    assert [m.module_id for m in all_modules()] == ["first", "second", "third"]


def test_all_modules_returns_a_fresh_list() -> None:
    register(_make_module("a"))
    snapshot = all_modules()
    snapshot.clear()
    assert len(all_modules()) == 1


# --- detect (rules 18-20) ---------------------------------------------------


def test_detect_returns_first_matching_module() -> None:
    register(_make_module("a", matches_result=False))
    register(_make_module("b", matches_result=True))
    register(_make_module("c", matches_result=True))
    found = detect(object())
    assert found is not None
    assert found.module_id == "b"


def test_detect_returns_none_when_no_module_matches() -> None:
    register(_make_module("a", matches_result=False))
    assert detect(object()) is None


def test_detect_returns_none_on_empty_registry() -> None:
    assert detect(object()) is None


def test_detect_stops_walking_after_first_match() -> None:
    calls: list[str] = []

    def _tracked_module(module_id: str, result: bool) -> type[TrackerModule]:
        class _Mod(TrackerModule):
            pass

        _Mod.module_id = module_id
        _Mod.module_name = module_id

        def _matches(self, event):  # noqa: ARG001
            calls.append(module_id)
            return result

        def _parse(self, event):  # noqa: ARG001
            return Hit(
                module_id=module_id, module_name=module_id, url="", host="",
                method="GET", response_status=None, started_at="",
            )

        _Mod.matches = _matches  # type: ignore[assignment]
        _Mod.parse = _parse  # type: ignore[assignment]
        return _Mod

    register(_tracked_module("a", False))
    register(_tracked_module("b", True))
    register(_tracked_module("c", False))
    detect(object())
    assert calls == ["a", "b"]


# --- reset_registry (rule 21) -----------------------------------------------


def test_reset_registry_empties_the_registry() -> None:
    register(_make_module("a"))
    register(_make_module("b"))
    reset_registry()
    assert all_modules() == []


def test_reset_registry_is_idempotent_on_empty() -> None:
    reset_registry()
    reset_registry()
    assert all_modules() == []