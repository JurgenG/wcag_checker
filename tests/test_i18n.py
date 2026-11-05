"""Tests for the translation layer and the completeness of its catalogs.

The catalog tests scan the package source for every English string passed
to ``tr(lang, "...")`` or marked with ``N_("...")`` (plus the manual
checklist's question table) and require each non-source catalog to
translate exactly that set, with the same ``{placeholders}``.
"""

from __future__ import annotations

import ast
import json
import string
from pathlib import Path

import pytest

from leak_inspector import i18n
from leak_inspector.i18n import (
    CATALOGS,
    CRITERION_NAMES,
    DEFAULT_LANG,
    LANGUAGES,
    N_,
    SOURCE_LANG,
    check_lang,
    criterion_name,
    tr,
)
from leak_inspector.wcag import axe_runner, manual_checklist
from leak_inspector.wcag.core import CRITERIA_BY_ID

PACKAGE = Path(i18n.__file__).resolve().parents[1]


def _source_files() -> list[Path]:
    """Every module of the package except the catalogs themselves."""
    return [
        p
        for p in PACKAGE.rglob("*.py")
        if "i18n" not in p.relative_to(PACKAGE).parts
    ]


def _call_name(node: ast.Call) -> str | None:
    func = node.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return None


def _msgids() -> dict[str, str]:
    """Map every translatable source string to the file that uses it."""
    found: dict[str, str] = {}
    for path in _source_files():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = _call_name(node)
            if name == "tr" and len(node.args) >= 2:
                arg = node.args[1]
            elif name == "N_" and node.args:
                arg = node.args[0]
            else:
                continue
            if isinstance(arg, ast.JoinedStr):
                pytest.fail(f"{path.name}: f-string passed to {name}(); use placeholders")
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                found.setdefault(arg.value, path.name)
    for questions in manual_checklist.QUESTIONS.values():
        for question in questions:
            found.setdefault(question, "manual_checklist.py")
    return found


def _fields(text: str) -> set[str]:
    return {f for _, f, _, _ in string.Formatter().parse(text) if f is not None}


class TestTranslate:
    def test_source_language_is_identity(self) -> None:
        assert tr("en", "Hello {name}", name="x") == "Hello x"

    def test_unknown_text_falls_back_to_english(self) -> None:
        assert tr("nl", "not in any catalog {n}", n=1) == "not in any catalog 1"

    def test_without_params_braces_are_left_alone(self) -> None:
        assert tr("en", "default: %(default)s {x}") == "default: %(default)s {x}"

    def test_marker_returns_text_unchanged(self) -> None:
        assert N_("abc") == "abc"

    def test_criterion_name(self) -> None:
        assert criterion_name("nl", "1.4.3", "Contrast (Minimum)") == "Contrast (minimum)"
        assert criterion_name("en", "1.4.3", "Contrast (Minimum)") == "Contrast (Minimum)"

    def test_check_lang(self) -> None:
        assert check_lang("nl") == "nl"
        with pytest.raises(ValueError):
            check_lang("xx")

    def test_defaults(self) -> None:
        assert SOURCE_LANG == "en"
        assert DEFAULT_LANG == "nl"
        assert set(CATALOGS) == set(LANGUAGES) - {SOURCE_LANG}


@pytest.mark.parametrize("lang", sorted(CATALOGS))
class TestCatalogCompleteness:
    def test_every_source_string_is_translated(self, lang: str) -> None:
        missing = sorted(
            f"{where}: {text!r}"
            for text, where in _msgids().items()
            if text not in CATALOGS[lang]
        )
        assert not missing, "\n".join(missing)

    def test_no_stale_entries(self, lang: str) -> None:
        stale = sorted(set(CATALOGS[lang]) - set(_msgids()))
        assert not stale, "\n".join(map(repr, stale))

    def test_placeholders_match(self, lang: str) -> None:
        bad = [
            text
            for text, translation in CATALOGS[lang].items()
            if _fields(text) != _fields(translation)
        ]
        assert not bad, "\n".join(map(repr, bad))

    def test_translations_are_not_empty(self, lang: str) -> None:
        assert all(v.strip() for v in CATALOGS[lang].values())

    def test_every_criterion_has_a_name(self, lang: str) -> None:
        assert set(CRITERION_NAMES[lang]) == set(CRITERIA_BY_ID)

    def test_axe_locale_is_bundled(self, lang: str) -> None:
        locale = axe_runner.axe_locale(lang)
        assert locale["lang"] == lang
        assert locale["rules"] and locale["checks"]
        json.dumps(locale)
