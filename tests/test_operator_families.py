"""Tests for ``leak_inspector.analysis.operator_families``.

Covers the 14 spec rules across 3 groups: FAMILIES data shape,
operator_label lookup, same_operator equivalence.
"""

from __future__ import annotations

import pytest

from leak_inspector.analysis.operator_families import (
    FAMILIES,
    operator_label,
    same_operator,
)


# --- A. FAMILIES data -------------------------------------------------------


def test_families_is_a_dict() -> None:
    assert isinstance(FAMILIES, dict)


@pytest.mark.parametrize(
    "operator",
    ["Microsoft", "Google", "Adobe", "Meta", "Apple", "Amazon", "Yahoo"],
)
def test_families_contains_known_operators(operator: str) -> None:
    assert operator in FAMILIES


@pytest.mark.parametrize(
    "operator",
    ["Microsoft", "Google", "Adobe", "Meta", "Apple", "Amazon", "Yahoo"],
)
def test_families_values_are_frozensets(operator: str) -> None:
    assert isinstance(FAMILIES[operator], frozenset)


# --- B. operator_label ------------------------------------------------------


def test_operator_label_empty_string_returns_empty() -> None:
    assert operator_label("") == ""


def test_operator_label_unknown_domain_returns_empty() -> None:
    assert operator_label("nobody-owns-this.example") == ""


@pytest.mark.parametrize(
    ("domain", "expected"),
    [
        ("microsoft.com", "Microsoft"),
        ("azure.com", "Microsoft"),
        ("google.com", "Google"),
        ("youtube.com", "Google"),
        ("adobe.com", "Adobe"),
        ("facebook.com", "Meta"),
        ("apple.com", "Apple"),
        ("amazon.com", "Amazon"),
        ("yahoo.com", "Yahoo"),
    ],
)
def test_operator_label_known_domains(domain: str, expected: str) -> None:
    assert operator_label(domain) == expected


def test_operator_label_is_case_insensitive() -> None:
    assert operator_label("MICROSOFT.COM") == "Microsoft"
    assert operator_label("Google.Com") == "Google"


# --- C. same_operator -------------------------------------------------------


@pytest.mark.parametrize(
    ("a", "b"),
    [
        ("", ""),
        ("", "microsoft.com"),
        ("microsoft.com", ""),
    ],
)
def test_same_operator_false_when_either_input_empty(a: str, b: str) -> None:
    assert same_operator(a, b) is False


def test_same_operator_identical_known_domains() -> None:
    assert same_operator("microsoft.com", "microsoft.com") is True


def test_same_operator_identical_unknown_domains() -> None:
    assert same_operator("unknown.example", "unknown.example") is True


def test_same_operator_same_family() -> None:
    assert same_operator("microsoft.com", "azure.com") is True
    assert same_operator("google.com", "youtube.com") is True


def test_same_operator_different_families() -> None:
    assert same_operator("microsoft.com", "google.com") is False


def test_same_operator_known_vs_unknown() -> None:
    assert same_operator("microsoft.com", "totally-not-microsoft.example") is False


def test_same_operator_two_unknown_distinct_domains() -> None:
    assert same_operator("a.example", "b.example") is False


def test_same_operator_is_case_insensitive() -> None:
    assert same_operator("MICROSOFT.COM", "Azure.Com") is True
    assert same_operator("GOOGLE.com", "Google.com") is True