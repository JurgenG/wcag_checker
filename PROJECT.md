# wcag-checker — project design

`wcag-checker` records a real, human-driven Firefox session and audits
the pages the operator chooses for **WCAG 2.2 AA** conformance. It is a
fork of the `leak_inspector` privacy tool, mid-conversion: it keeps that
tool's browser-capture core (Selenium + Firefox + WebDriver BiDi) and its
report-shape philosophy, and replaces the tracker-analysis pipeline with
accessibility auditing.

This document is the design reference. `CLAUDE.md` is the working-rules
anchor; `leak_inspector/wcag/core.py` is the authoritative source for the
criteria registry. Where this file and the code disagree, the code wins —
update this file.

## The key design decision: audit live, not offline

The fork's model was **capture now, analyze offline later**: record every
request/response into a bundle, then run tracker modules over the frozen
bundle with no browser in the loop. That works for network traffic
because the bytes are the evidence.

Accessibility is different. The evidence for most WCAG criteria exists
*only in a live, fully-rendered browser*:

- **Colour contrast** (1.4.3/1.4.6) needs computed styles — resolved
  colours, fonts, and sizes after CSS cascade — not raw HTML.
- **Focus behaviour** (2.4.7/2.4.11, 2.1.2, 2.4.3) only exists while the
  page is interactive: you must move focus and observe what changes.
- **Target size** (2.5.8) needs laid-out bounding boxes.
- **Interaction-revealed content** — menus, dialogs, consent banners,
  client-side-rendered views — isn't in the initial DOM at all.

So `wcag-checker` departs from the fork: the audit runs **on the live
driver at the instant the operator presses the hotkey**, against exactly
the page state a real visitor is looking at. There is no offline
re-analysis phase — the judgement happens in the browser, and only the
findings are persisted.

## End-to-end flow

1. `wcag-checker <url> --out reports/` launches Firefox (BiDi enabled,
   visible window) and navigates to the URL.
2. The operator browses normally — clicking through flows, opening
   menus, dismissing or accepting banners, navigating between pages.
3. On any page worth checking, the operator presses the **audit hotkey**
   (`Ctrl+Alt+A`). The tool audits the current live page: axe-core scan
   + keyboard-navigation checks + an evidence screenshot. Findings are
   tagged with the page URL and accumulated in memory. The operator can
   press it on as many pages (or page states) as they like.
4. Closing the Firefox window ends the session. The tool writes the
   report set to `--out`.

Nothing is scripted or headless: focus and keyboard behaviour need a
real desktop and a window a human is driving.

## The hotkey mechanism

Reused verbatim from the fork's screenshot signal (see
`leak_inspector/capture/bidi.py`). At session start, a BiDi **preload
script** is injected into every browsing context. It binds the hotkey on
the document capture phase (so it fires before any page handler) and, on
press, issues a `fetch()` to a reserved `*.invalid` **sentinel host**
carrying the page host in a `?host=` query.

`.invalid` is RFC-2606-reserved, so the host never resolves — but BiDi's
`network.beforeRequestSent` fires *before* the fetch is even attempted.
The capture layer catches that request, **suppresses it** from the event
stream at every stage of the request lifecycle, and fires a Python
callback. That callback is the audit trigger: no OS-level keyboard hooks,
no extra subscriptions, no traffic leaking into results — a clean in-band
keypress → Python signal.

The fork bound `Ctrl+Alt+S` to grab a screenshot; `wcag-checker` binds
`Ctrl+Alt+A` to run an audit (which also captures a screenshot as
evidence). `Ctrl+Shift+S` is deliberately avoided — it's Firefox's own
screenshot shortcut, and `preventDefault` in a page handler does not
block Firefox chrome shortcuts.

## Modules and boundaries

Everything WCAG-specific lives under `leak_inspector/wcag/` (the
importable package is still named `leak_inspector` during conversion; the
user-facing command is `wcag-checker`).

- **`core.py`** — driver-free dataclasses (`WcagCriterion`, `Finding`)
  and `CRITERIA_REGISTRY`, all 87 WCAG 2.2 success criteria tagged with
  level (A/AA/AAA) and automatability tier. The single source of truth
  for coverage claims. Imports nothing browser- or driver-specific.
- **`axe_runner.py`** — wraps the axe-core engine via
  `axe-selenium-python` (bundles axe-core 4.10.2). Injects axe, runs it
  with the AA tag set, and normalizes violations + incomplete results
  into `Finding` objects. Any rule suppression carries an inline comment
  justifying the false-positive reasoning — findings are never silenced
  just to make a run green.
- **`keyboard_nav.py`** — the focus/keyboard-flow checks axe-core
  deliberately skips, the highest-value custom code:
  - focus visibility (2.4.7 / 2.4.11)
  - no keyboard trap (2.1.2)
  - tab / focus order vs. visual order (2.4.3)
  - target size (2.5.8)
- **`manual_checklist.py`** — generates the human-review checklist for
  the criteria that cannot be asserted automatically (the majority),
  pre-filled per page with the URL and any `needs-review` findings.
- **`reporter.py`** — merges findings grouped by WCAG criterion (not by
  rule id) and renders the output formats, always with a coverage
  summary. Pure: findings in, strings out.
- **Session runner + CLI** — orchestrates launch → per-hotkey live audit
  → report, and writes the files.

Clean-boundary rules:

- `core` imports none of the others; everything may import `core`.
- `axe_runner` and `keyboard_nav` take a **live driver handle from the
  caller** and run against it. They never launch, configure, or close the
  browser — the session layer owns the driver lifecycle.
- `reporter` is pure — it touches no network, driver, or filesystem. The
  CLI writes the files.
- `capture` drives the browser and raises the hotkey signal; it does not
  import `wcag`. The session runner wires the callback.

## WCAG methodology & automatability tiers

WCAG 2.2 defines 87 success criteria. Empirically ~30% are fully
automatable, ~10% partially, and ~60% require human judgement.
`core.py` tags every criterion with one tier:

- **`full`** — a tool can decide the automatable substance on its own
  (contrast, `lang` presence, name/role/value, page title, bypass
  blocks). A machine pass is meaningful evidence.
- **`partial`** — a tool flags *candidates*; a human confirms (link-text
  quality, reflow, target size, focus order, headings/labels).
- **`manual`** — needs human judgement; no assertion is emitted, only a
  checklist item (meaningful-vs-present alt text, error-message quality,
  plain language, media alternatives, consistent navigation).

The central honesty stance: **a clean automated run is not conformance.**
A `full`-tier pass means only that the automatable part found no defect —
it says nothing about the criterion's manual aspects. The tiers describe
*coverage*, never conformance, and every report states this explicitly.
Never claim automated coverage of a criterion the engine cannot actually
decide; when unsure, a criterion is `manual`.

axe-core is run with the AA tag set:
`wcag2a`, `wcag2aa`, `wcag21a`, `wcag21aa`, `wcag22aa`.

## Report structure

Written to the `--out` directory on session close:

- **`results.json`** — the canonical machine-readable record: every
  finding (criterion, severity, message, selector, page URL), the pages
  audited, and the coverage summary. All other formats derive from it.
- **text** — a terminal-readable report.
- **Markdown** — a shareable report.
- **HTML** — a single self-contained page (inline CSS, no external
  assets), suitable for opening in a browser or attaching to a ticket.
- **manual checklist** — the human-review items for the non-automatable
  criteria, per audited page.
- **evidence screenshots** — one per hotkey press, referenced by the
  report.

Findings are **grouped by WCAG success criterion**, not by axe rule id,
so a reader sees the report in the vocabulary of the standard. Severity
is `error` (definite failure), `warning` (lower-impact definite failure),
or `needs-review` (a candidate the tool cannot confirm — axe "incomplete"
results and partial-tier keyboard checks). Every report leads with a
**coverage summary**: how many criteria were actually exercised, and the
standing reminder that manual review is still required.

## Non-goals

- **Headless / scripted browsing** — focus and keyboard behaviour need a
  real desktop and a visible, human-driven window.
- **Browsers other than Firefox.**
- **Screen-reader announcement testing** (NVDA/JAWS/VoiceOver scripting)
  — marked manual.
- **Content-quality heuristics** (plain language, error-message
  helpfulness) — marked manual; shipping a noisy heuristic is worse than
  an honest checklist item.
- **Always-on monitoring** and **active remediation** — this audits, it
  does not fix or continuously watch.
- **PDF export.**
- **Silent axe suppressions** — every exclusion needs a justifying
  comment.

## Stack

- Python ≥ 3.12, fully synchronous.
- Runtime deps: `selenium` (drives Firefox and writes the element
  screenshots) and `axe-selenium-python` (bundles axe-core 4.10.2).
- System deps: Firefox + geckodriver (auto-provisioned by Selenium
  Manager).
- Tests: `pytest`, hermetic (no live browser / network) for the pure
  logic; live checks guarded on Firefox availability.
- License: **GPL-3.0-or-later**.