# wcag_checker — record a real human-driven browsing session and audit
# the visited pages for WCAG 2.2 accessibility conformance.
# Copyright (C) 2026 Jurgen Gaeremyn
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

"""Poll-based audit hotkey.

Lets the operator trigger an audit by pressing a keyboard shortcut in the
browsed page. Each poll runs one ``execute_script`` that (1) installs a
``keydown`` listener in the page — once per document — which increments a
counter when the hotkey matches, and (2) reads and clears that counter.
The session loop polls on a timer and audits whenever the count is
non-zero.

Why polling instead of a network signal: the previous design had the
in-page handler ``fetch()`` a sentinel host that a BiDi network event
caught. But a page's ``Content-Security-Policy: connect-src`` blocks that
fetch before it is sent, so the signal never arrived on any site with a
CSP — which is most real sites. Reading a counter via ``execute_script``
touches no network and no ``<script>``/``eval``, so CSP does not affect
it, and re-installing on each fresh document handles navigation.

The hotkey is a ``+``-separated spec (e.g. ``ctrl+alt+shift+a``, ``f9``):
modifiers plus exactly one key, matched by ``KeyboardEvent.code`` so the
match is unaffected by keyboard layout or by Alt remapping the character.
The parsing/JS helpers are pure and unit-tested; only :meth:`HotkeyWatcher.poll`
needs a live driver.
"""

from __future__ import annotations

from typing import Any

from selenium.common.exceptions import WebDriverException

#: Default audit hotkey. Ctrl+Alt+Shift+A: three modifiers make it far
#: less likely than a plain Ctrl+Alt combo to be grabbed by the window
#: manager or by Firefox's own chrome shortcuts, and it won't be pressed
#: by accident. Override via ``--hotkey`` if a desktop still grabs it.
DEFAULT_HOTKEY = "ctrl+alt+shift+a"

#: Modifier tokens accepted in a hotkey spec, mapped to their DOM event
#: flag. An exact match is required: a modifier absent from the spec must
#: be *up*, so ``ctrl+alt+shift+a`` does not also fire on ``ctrl+alt+a``.
_MODIFIER_FLAGS = {
    "ctrl": "e.ctrlKey",
    "alt": "e.altKey",
    "shift": "e.shiftKey",
    "meta": "e.metaKey",
}


def _key_code(token: str) -> str:
    """Map a hotkey key token to its layout-independent ``KeyboardEvent.code``.

    Letters ``a``–``z`` → ``KeyA``…, digits ``0``–``9`` → ``Digit0``…, and
    ``f1``–``f12`` → ``F1``…. Raises :class:`ValueError` otherwise.
    """
    t = token.lower()
    if len(t) == 1 and "a" <= t <= "z":
        return "Key" + t.upper()
    if len(t) == 1 and t.isdigit():
        return "Digit" + t
    if t.startswith("f") and t[1:].isdigit() and 1 <= int(t[1:]) <= 12:
        return "F" + t[1:]
    raise ValueError(f"unsupported hotkey key: {token!r}")


def hotkey_condition(spec: str) -> str:
    """Compile a hotkey spec (e.g. ``ctrl+alt+shift+a``, ``f9``) to a JS test.

    Returns a JavaScript boolean expression over a ``keydown`` event ``e``
    that is true only for an exact match — every named modifier down, every
    unnamed modifier up, and the key's ``e.code``. Raises
    :class:`ValueError` for an empty spec, an unknown modifier, or anything
    other than exactly one non-modifier key.
    """
    tokens = [p.strip().lower() for p in spec.split("+") if p.strip()]
    if not tokens:
        raise ValueError("empty hotkey")
    keys = [t for t in tokens if t not in _MODIFIER_FLAGS]
    mods = [t for t in tokens if t in _MODIFIER_FLAGS]
    if len(keys) != 1:
        raise ValueError(
            f"hotkey must name exactly one non-modifier key, got {keys!r}"
        )
    code = _key_code(keys[0])
    parts = [
        flag if name in mods else f"!{flag}"
        for name, flag in _MODIFIER_FLAGS.items()
    ]
    parts.append(f"e.code === '{code}'")
    return " && ".join(parts)


def format_hotkey(spec: str) -> str:
    """Render a hotkey spec for display, e.g. ``ctrl+alt+shift+a`` → ``Ctrl+Alt+Shift+A``."""
    out = []
    for token in (p.strip() for p in spec.split("+") if p.strip()):
        out.append(token.capitalize() if token.lower() in _MODIFIER_FLAGS else token.upper())
    return "+".join(out)


def poll_script(spec: str) -> str:
    """Build the per-tick ``execute_script`` body for ``spec``.

    The script installs the keydown listener once per document (guarded by
    a window flag, so a fresh document after navigation reinstalls it) and
    returns the number of matching presses since the previous poll,
    clearing the counter. Building it validates the spec.
    """
    return _POLL_TEMPLATE.replace("__CONDITION__", hotkey_condition(spec))


#: ``execute_script`` wraps this in a function body, so ``return`` is valid.
_POLL_TEMPLATE = """
if (!window.__wcagHotkeyInstalled) {
  window.__wcagHotkeyInstalled = true;
  window.__wcagHotkeyPending = 0;
  document.addEventListener('keydown', function(e) {
    if (!(__CONDITION__)) return;
    e.preventDefault();
    e.stopPropagation();
    window.__wcagHotkeyPending = (window.__wcagHotkeyPending || 0) + 1;
  }, true);
}
var n = window.__wcagHotkeyPending || 0;
window.__wcagHotkeyPending = 0;
return n;
"""


class HotkeyWatcher:
    """Install the audit hotkey in the live page and report presses.

    Construct with the driver and a hotkey spec (validated up front, raising
    :class:`ValueError` on a bad one), then call :meth:`poll` on a timer.
    Each :meth:`poll` ensures the listener is installed in the current
    document and returns how many times the hotkey was pressed since the
    last poll.
    """

    def __init__(self, driver: Any, *, hotkey: str = DEFAULT_HOTKEY) -> None:
        self._driver = driver
        self._script = poll_script(hotkey)

    def poll(self) -> int:
        """Return the number of hotkey presses since the last poll.

        Runs one ``execute_script`` (installing the listener if the current
        document doesn't have it yet). Returns 0 on any transient WebDriver
        error — e.g. mid-navigation — so the caller just tries again next
        tick.
        """
        try:
            count = self._driver.execute_script(self._script)
        except WebDriverException:
            return 0
        return int(count) if isinstance(count, (int, float)) else 0


__all__ = [
    "DEFAULT_HOTKEY",
    "HotkeyWatcher",
    "format_hotkey",
    "hotkey_condition",
    "poll_script",
]
