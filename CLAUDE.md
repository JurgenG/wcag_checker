# CLAUDE.md

Guidelines for Claude when working in this repository.

## This project

`wcag-checker` audits web pages for **WCAG 2.2 AA** accessibility in a
real, human-driven Firefox session. The operator opens the tool on a URL,
browses normally, and presses an **audit hotkey** on any page they want
checked. The audit runs against the *live, fully-rendered* page — including
content behind interaction, consent banners, and client-side rendering.
When the operator closes the browser, the reports are written.

Only base modules on certain data; if you cannot find reliable
information, don't speculate. Never claim automated coverage of a WCAG
criterion the underlying engine cannot actually decide — an honest
"needs manual review" is always better than a false pass.

## Architecture

- **Capture** (`leak_inspector/capture/`)
  - `driver.py` — Selenium drives Firefox via geckodriver over WebDriver
    BiDi. Downloads a private Firefox when none is installed.
  - `hotkey.py` — `HotkeyWatcher`: each poll runs one `execute_script`
    that installs a `keydown` listener once per document and reads/clears
    a press counter. Default `F9` (`--hotkey`), matched by
    `KeyboardEvent.code` (layout-independent). The trigger must stay
    CSP-immune: never signal via a page-originated network request
    (`connect-src` blocks it).
- **WCAG audit** (`leak_inspector/wcag/`) — runs on the live driver when
  the hotkey fires:
  - `core.py` — driver-free `WcagCriterion` / `Finding` dataclasses and
    the WCAG 2.2 registry with each criterion's automatability tier
    (`full` / `partial` / `manual`). Single source of truth for coverage
    claims.
  - `axe_runner.py` — runs axe-core (via `axe-selenium-python`) and
    normalizes violations/incomplete results into `Finding`s. Enables
    axe's experimental `label-content-name-mismatch` rule for 2.5.3.
  - `keyboard_nav.py` — focus/keyboard checks axe-core skips: focus
    visibility (2.4.7 / 2.4.11), keyboard traps (2.1.2), tab order
    (2.4.3), target size (2.5.8).
  - `media.py` — `needs-review` media inventory: native `<audio>` → 1.2.1,
    native `<video>` → 1.2.3 (listing detected `<track>`s), YouTube/Vimeo
    embeds → 1.2.2 + 1.2.3, other `<iframe>`s → 1.2.1. axe owns 1.2.2 for
    native video and 1.4.2; media's 1.2.2 covers only embeds.
  - `pointers.py` — `needs-review` pointers to the elements a manual
    criterion hinges on: 4.1.3 live regions, 3.3.8 password fields +
    CAPTCHA, 2.4.5 search/nav/sitemap, 3.2.6 help/contact.
  - `content.py` — 2.4.4 generic link text and 2.4.6 empty headings,
    `needs-review`.
  - `reflow.py` — 1.4.10: sets a 320 CSS-px viewport via BiDi
    `browsing_context.set_viewport`, flags horizontal overflow, restores
    the viewport.
  - `screenshot.py` — one PNG per flagged element, deduped by
    `(url, selector)`.
  - `text_view.py` — linearized reading view (accessible-name tree in
    source order), embedded in every report. A reading aid, no pass/fail.
  - `manual_checklist.py` — per-criterion review questions for the
    criteria tooling cannot decide.
  - `reporter.py` — groups findings by criterion and renders JSON
    (canonical), text, Markdown, HTML and JIRA tickets, always with a
    coverage summary.
- **Session + CLI** — `session.py` (interactive and `--once` runs),
  `batch.py` (URL lists), `cli.py` / `cli_batch.py` (argument parsing).
  Reports are written on window close.

Boundaries to keep clean:

- `core` imports nothing browser- or driver-specific; everything may
  import `core`.
- Checks take a live driver handle from the caller. They never launch,
  configure, or close the browser — the session layer owns that.
- `reporter` is pure: findings in, strings out. The CLI writes files.
- `capture` does not import `wcag`; the session runner polls the watcher
  and runs the audit.

Constraints:

- Firefox only, visible desktop window (focus and keyboard behavior need
  one).
- Screen-reader announcement testing and content-quality judgements
  (plain language, error-message helpfulness) stay in the manual
  checklist — don't ship noisy heuristics.
- Every axe rule exclusion carries a justifying comment.
- Every report states that a clean automated run is not WCAG conformance.

## Code standards

- Follow PEP 8 (style), PEP 257 (docstrings), PEP 484 / PEP 604 (type
  hints on public functions and methods), PEP 20 (simple, explicit).
- Fully synchronous — no async.
- Match the existing style; don't introduce a formatter/linter without
  asking.
- Small, focused modules and short functions; separate parsing, logic,
  I/O and presentation. Prefer pure functions; isolate driver side
  effects. Keep public interfaces minimal.

## Code documentation

- Every module, public class, and public function gets a docstring
  describing **purpose, inputs, outputs, and side effects**.
- Each WCAG check names the criterion id(s) it supports in its docstring.
- Inline comments are rare and explain a non-obvious *why*.

## Project documentation

Applies to README.md, INSTALL.md, PROJECT.md, docs/ and SBOM.md:

- **Current state only.** Write as if the project were new. No history,
  no "previously", no "was removed", no fork lineage.
- **Explain what it does.** Don't list what it doesn't do, what was
  dropped, or how a decision was reached.
- **Tutorials assume nothing.** Step-by-step guides assume no prior
  knowledge and nothing installed, and cover macOS, Windows and Linux.
- Update the relevant docs when behavior or interfaces change.
- Keep `TODO.md` as the task queue and `SBOM.md` as the dependency list
  with its maintenance processes.

## Testing (TDD)

- Every new feature gets a test (`tests/`, pytest).
- Unit tests are hermetic — no live browser, no network. Test the pure
  decision logic against canned data and fixtures.
- Each `keyboard_nav` check gets a known-good and a known-bad fixture.
- A check returns `list[Finding]` and raises only for real execution
  errors, never for "issues found".

## Scope discipline

- **Do only what is asked.** No unrequested features, options,
  abstractions, refactors, or extra error handling. If you spot something
  worth changing, mention it and wait.
- Prefer editing existing files over creating new ones.

## When in doubt, ask

- If requirements are ambiguous or there are approaches with meaningful
  trade-offs, ask one short clarifying question before writing code, and
  surface assumptions explicitly.
