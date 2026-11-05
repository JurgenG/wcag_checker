# wcag-checker — design

`wcag-checker` audits web pages for **WCAG 2.2 AA** accessibility in a
real, human-driven Firefox session. This document describes how it is
built. [`leak_inspector/wcag/core.py`](leak_inspector/wcag/core.py) is
the authoritative source for the criteria registry; where this file and
the code differ, the code is right and this file gets updated.

## Live auditing

The audit runs inside the browser, on the page as it is on screen at the
moment the operator presses the hotkey. Much of WCAG can only be judged
on a live, rendered page:

- **Colour contrast** (1.4.3 / 1.4.6) uses computed styles: the colours,
  fonts and sizes after the CSS cascade.
- **Focus behaviour** (2.4.7 / 2.4.11, 2.1.2, 2.4.3) is observed by moving
  focus through the page.
- **Target size** (2.5.8) and **reflow** (1.4.10) use laid-out boxes.
- **Interaction-revealed content** — menus, dialogs, consent banners,
  client-side views — exists only after the operator has interacted.

Only the findings, screenshots and reading view are stored.

## End-to-end flow

1. `wcag-checker <url>` launches a visible Firefox (WebDriver BiDi
   enabled, fresh temporary profile) and opens the URL.
2. The operator browses: clicks through flows, opens menus, handles
   banners, logs in.
3. On each page worth checking, the operator presses the audit hotkey
   (`F9` by default). The tool audits the live page, tags every finding
   with the page URL, captures a screenshot per flagged element, and
   keeps the results in memory.
4. Closing the Firefox window ends the session; the reports are written
   to `<out>/<host>/` with a `YYYYMMDDHHMM_` prefix on each filename.

`--once` runs steps 1, 3 and 4 automatically for a single page, after
waiting for the page to settle. `wcag-batch` does the same for every URL
in a list, reusing one Firefox, and writes a summary across sites.

## The hotkey

`capture/hotkey.py` provides `HotkeyWatcher`. The session loop polls it
on a timer. Each poll runs one `execute_script` call that:

1. installs a `keydown` listener in the current document if it is not
   there yet (so it is re-installed after every navigation), and
2. reads and resets a counter of hotkey presses.

When the count is non-zero, the session runs an audit. The key is matched
by `KeyboardEvent.code`, so it works the same on every keyboard layout,
and modifiers must match exactly (`ctrl+alt+shift+a` does not fire on
`ctrl+alt+a`). Reading the counter uses only the WebDriver channel, so
it works on pages with a strict Content-Security-Policy.

## Modules

The Python package is `leak_inspector`; the commands are `wcag-checker`
and `wcag-batch`.

**Capture** (`leak_inspector/capture/`)

- `driver.py` — launches Firefox through Selenium and geckodriver with
  WebDriver BiDi, applies `--width`, and downloads a private Firefox when
  none is installed.
- `hotkey.py` — the hotkey watcher described above.

**Audit** (`leak_inspector/wcag/`)

- `core.py` — driver-free dataclasses (`WcagCriterion`, `Finding`) and
  `CRITERIA_REGISTRY`: all 86 WCAG 2.2 success criteria with level
  (A / AA / AAA) and coverage tier.
- `axe_runner.py` — injects axe-core (bundled by `axe-selenium-python`),
  runs it with the `wcag2a`, `wcag2aa`, `wcag21a`, `wcag21aa` and
  `wcag22aa` tags plus the `label-content-name-mismatch` rule, and turns
  violations and incomplete results into `Finding`s grouped by WCAG
  criterion.
- `keyboard_nav.py` — focus visibility (2.4.7 / 2.4.11), keyboard traps
  (2.1.2), focus order (2.4.3) and target size (2.5.8).
- `media.py` — inventory of audio, video and embedded media (1.2.1,
  1.2.2, 1.2.3).
- `pointers.py` — review pointers to the elements behind 4.1.3, 3.3.8,
  2.4.5 and 3.2.6.
- `content.py` — generic link text (2.4.4) and empty headings (2.4.6).
- `reflow.py` — 320 CSS-px viewport check for horizontal scrolling
  (1.4.10); restores the operator's viewport afterwards.
- `screenshot.py` — one PNG per flagged element, with the element
  outlined.
- `text_view.py` — the linearized reading view.
- `manual_checklist.py` — step-by-step review questions per criterion,
  per audited page.
- `reporter.py` — builds one report document and renders it as JSON,
  text, Markdown, HTML and JIRA tickets.

**Session and CLI** (`leak_inspector/`)

- `session.py` — interactive and `--once` runs: launch, poll, audit,
  write reports.
- `batch.py` — URL-list runs and the cross-site summary.
- `cli.py`, `cli_batch.py` — argument parsing for `wcag-checker` and
  `wcag-batch`.

Each check splits into an impure **gatherer** (reads the live page) and
a pure **evaluator** (turns the gathered data into findings),
so the decision logic is unit-tested without a browser.

### Boundaries

- `core` imports nothing browser- or driver-specific; every other module
  may import it.
- Checks receive a live driver from the session. The session owns the
  browser's lifecycle.
- `reporter` is pure: findings in, text out. The CLI writes the files.
- `capture` does not import `wcag`; the session connects them.

## Coverage tiers

`core.py` gives every criterion one tier:

- **full** — the tool decides the automatable part (contrast, page
  language, name/role/value, page title, bypass blocks).
- **partial** — the tool flags candidates; a person confirms (link text,
  reflow, target size, focus order, headings).
- **manual** — a person decides, guided by the checklist and review
  pointers (meaningful alt text, error-message quality, plain language,
  consistent navigation).

A criterion is tiered `full` only when the engine fully decides its
automatable part. Every report shows the tier of every A + AA criterion
and reminds the reader that conformance combines the automated results
with the manual review. [docs/COVERAGE.md](docs/COVERAGE.md) lists
the tiers in full.

## Reports

Written on session close, per website:

- **`results.json`** — every finding (criterion, severity, impact,
  message, selector, page URL, screenshot path), the coverage table and
  the reading view.
- **`report.html`**, **`report.md`**, **`report.txt`** — the same
  content for people; HTML is a single file with inline styling.
- **`jira/`** — one ticket per WCAG criterion.
- **`manual-checklist.md`** — always written.
- **`screenshots/`** — always written.

Findings are grouped by WCAG success criterion and ordered by priority
band (P1–P4). Severity is `error`, `warning` or `needs-review`; axe-core's
grading is kept as `impact`. Every report opens with the priority
overview and a coverage summary.

## Stack

- Python 3.12 or newer, fully synchronous.
- `selenium` (drives Firefox, takes element screenshots) and
  `axe-selenium-python` (bundles axe-core 4.10.2).
- Firefox and geckodriver (geckodriver is downloaded automatically by
  Selenium Manager).
- Tests: `pytest`, hermetic — the pure logic is tested against canned
  data, without a browser or network.
- License: GPL-3.0-or-later.
