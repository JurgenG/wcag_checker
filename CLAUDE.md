# CLAUDE.md

Guidelines for Claude when working in this repository.

## This project

`wcag-checker` records a real, human-driven browsing session in Firefox
and audits the visited pages for **WCAG 2.2 AA** accessibility
conformance. The operator opens the tool on a URL, browses the site
normally, and presses an **audit hotkey** on any page they want checked.
At that moment the tool runs an accessibility audit against the *live,
fully-rendered* page — the state a real visitor sees, including content
behind interaction, consent banners, and client-side rendering. When the
operator closes the browser, a report is written.

This is a fork of the `leak_inspector` privacy tool. It reuses that
tool's browser-capture core (Selenium + Firefox + WebDriver BiDi) and its
report-shape philosophy, but replaces the entire tracker-analysis
pipeline with WCAG auditing.

If you don't have enough information online or cannot reliably build a
module, don't speculate. Only base modules on certain data. In
particular, never claim automated coverage of a WCAG criterion that the
underlying engine cannot actually decide — an honest "needs manual
review" is always better than a false pass.

## Architecture

- **Capture / session** (`leak_inspector/capture/`) — Selenium drives
  Firefox via geckodriver, using WebDriver BiDi. The user clicks around
  manually; the tool holds the session open and listens for the audit
  hotkey. Reused from the fork mostly unchanged.
- **Hotkey trigger** (`leak_inspector/capture/bidi.py`) — a BiDi preload
  script injected into every browsing context binds the audit hotkey
  (`Ctrl+Alt+A`). The keypress fires a `fetch()` to a reserved
  `.invalid` sentinel host; BiDi's `network.beforeRequestSent` catches
  it and fires a Python callback. This is the same in-band
  keypress→callback signal the fork used for screenshots — no OS-level
  hooks needed. (Only the signal survives the conversion; the fork's
  network/event recorder was removed.)
- **WCAG audit** (`leak_inspector/wcag/`) — runs on the live driver when
  the hotkey fires:
  - `core.py` — driver-free dataclasses (`WcagCriterion`, `Finding`) and
    the WCAG 2.2 criteria registry with per-criterion automatability tier
    (`full` / `partial` / `manual`). The single source of truth for
    coverage claims. No driver import.
  - `axe_runner.py` — wraps the axe-core engine (via
    `axe-selenium-python`) and normalizes its violations/incomplete
    results into `Finding` objects. Takes the driver as-is; never creates
    or owns the browser session.
  - `keyboard_nav.py` — focus/keyboard-flow checks axe-core deliberately
    skips (focus visibility, keyboard traps, tab order, target size).
    The highest-value custom code.
  - `manual_checklist.py` — generates the human-review checklist for the
    majority of criteria that cannot be asserted automatically.
  - `text_view.py` — produces an approximate *linearized reading view* of
    the live page (accessible-name tree walked in source order), written
    as a manual-review aid. Takes a live driver like `axe_runner`; makes
    no pass/fail claim (a reading aid, not a screen-reader test).
  - `reporter.py` — merges findings grouped by WCAG criterion and renders
    JSON (canonical) + text + Markdown + HTML, always with a coverage
    summary. Pure: findings in, strings out.
- **Session runner + CLI** — orchestrates capture → per-page audit →
  report. On window close, writes reports and a canonical `results.json`
  to the output directory.

Boundaries to keep clean:

- `core/` imports nothing browser- or driver-specific. Everything else
  may import `core`; `core` imports none of them.
- `axe_runner/` and `keyboard_nav/` take a live driver handle from the
  caller and run against it. They do not launch, configure, or close the
  browser — the session layer owns that.
- `reporter/` is pure: it consumes `Finding` lists + the registry and
  emits text. It does not touch the network, the driver, or the
  filesystem (the CLI writes the files).
- `capture/` drives the browser and raises the hotkey signal. It does not
  import `wcag/`; the session runner wires the callback.

Explicit non-goals: headless/scripted browsing (focus and keyboard
behavior need a real desktop and a visible window), browsers other than
Firefox, screen-reader announcement testing (NVDA/JAWS/VoiceOver
scripting — mark manual), content-quality heuristics (plain language,
error-message helpfulness — mark manual, don't ship noise), and silent
axe rule suppressions (every exclusion needs a justifying comment). A
clean automated run does **not** imply WCAG conformance; the report
always says so.

## Code standards

- Adhere to Python PEP standards, in particular:
  - **PEP 8** — code style (naming, indentation, line length, imports).
  - **PEP 257** — docstring conventions.
  - **PEP 484 / PEP 604** — type hints; annotate public functions and methods.
  - **PEP 20** (Zen of Python) — prefer simple, explicit, readable code.
- The codebase is fully synchronous — do not introduce async.
- Match the existing style; do not introduce a new formatter/linter
  without asking.
- Write modular code, prefer small functions over large blobs.

## Documentation

- Every module, public class, and public function gets a docstring (PEP 257).
- Docstrings describe **purpose, inputs, outputs, and side effects** — not implementation details that the code already shows.
- Keep inline comments rare and reserved for non-obvious *why*, not *what*.
- Each WCAG check documents the criterion id(s) it supports in its docstring.
- Update relevant docs (README, module docstrings) when behavior or interfaces change.
- Create/use TODO.md in the project root when new tasks are added to a queue.
- Create/use SBOM.md to maintain an SBOM and comment on the key processes.

## Modular development

- Build small, focused modules with clear single responsibilities.
- Keep functions short; extract helpers when a function does more than one thing.
- Separate concerns: parsing, business logic, I/O, and presentation live in distinct modules.
- Prefer pure functions where practical; isolate side effects (esp. the driver).
- Public interfaces should be minimal and explicit; avoid leaking internals.

## Testing (TDD)

- Build a test for every new feature that gets added (`tests/`, pytest).
- Unit tests are hermetic — no live browser, no network. Test the pure
  decision logic (registry, axe-output normalization, keyboard-check
  helpers, report rendering) against canned data and fixtures.
- Each `keyboard_nav` check gets a known-good and known-bad fixture so
  correctness isn't only validated against live external sites.
- A check returns `list[Finding]` and never raises for "issues found" —
  only for real execution errors (page crashed, selector failed).

## Scope discipline

- **Do only what is asked.** Do not add features, options, configuration, abstractions, or "nice-to-haves" that were not requested.
- No speculative generality — no hooks, plugin systems, or extension points for hypothetical future needs.
- No unrequested refactors. If you spot something worth changing, mention it and wait for direction.
- No extra error handling, logging, retries, or validation beyond what the task requires or what is needed at real system boundaries.
- Prefer editing existing files over creating new ones.

## When in doubt, ask

- If requirements are ambiguous, the desired scope is unclear, or there are multiple reasonable approaches with meaningful trade-offs, **ask a clarifying question before writing code**.
- Surface assumptions explicitly rather than silently choosing.
- It is always better to ask one short question than to deliver the wrong thing.