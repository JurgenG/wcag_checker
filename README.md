# wcag-checker

Audit a **live, fully-rendered** web page for **WCAG 2.2 AA**
accessibility conformance — the page as a real visitor's browser actually
renders it, including client-side content and state behind a dismissed
consent banner.

Most accessibility scanners fetch a URL and audit whatever the server
returns, missing everything that only exists after the browser runs the
page. `wcag-checker` instead drives a real Firefox and audits the DOM as
it actually stands.

> **Honest by design.** WCAG 2.2 has 87 success criteria; only a minority
> can be decided by a machine. A clean run from this tool is **not** a
> statement of conformance — it means the *automatable* checks found no
> defect. See [Coverage & honesty](#coverage--honesty). Green never means
> done.

## Project status

The tool is **mid-build**. Here is what works today and what does not:

| Part | Status |
| --- | --- |
| axe-core audit (WCAG 2.2 AA rule tags) → findings | ✅ working |
| Keyboard / focus checks axe skips (focus visible, keyboard trap, focus order, target size) | ✅ working |
| Report renderer — `results.json` + text + Markdown + HTML, with coverage summary | ✅ working |
| Single-page audit runner (`tools/wcag_smoke.py`) | ✅ working |
| Interactive **hotkey** session (browse by hand, press `Ctrl+Alt+A` per page) | 🚧 not built yet |
| `wcag-checker` console command, screenshots, manual-review checklist | 🚧 not built yet |

So today you audit **one page's rendered state at a time** through the
`wcag_smoke.py` runner (below). The hand-driven, multi-page hotkey
workflow is the design goal — see [Roadmap](#roadmap).

## Requirements

- **Python 3.12+**
- A **real, visible desktop** — the keyboard/focus checks move focus and
  measure the rendered page, so there is no headless-server story (a
  `--headless` flag exists but a real display is still recommended).
- **Firefox.** geckodriver is fetched automatically by Selenium; if
  Firefox itself is missing, a private copy is downloaded on first run.

## Install

See [INSTALL.md](INSTALL.md) for a step-by-step, zero-experience guide
(Windows / macOS / Linux). The short version:

```bash
git clone <your-repository-url> wcag-checker
cd wcag-checker
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate.bat
pip install -e .
pip install axe-selenium-python    # audit engine (not yet a declared dep)
```

> `axe-selenium-python` is installed separately for now — it will move
> into the package dependencies once packaging is finalized.

## Usage

Audit the rendered state of a page:

```bash
python tools/wcag_smoke.py https://example.com --out reports/
```

What happens:

1. A visible Firefox window opens and navigates to the URL.
2. The tool audits the DOM **as rendered at that moment** — axe-core's
   WCAG 2.2 AA rules plus the keyboard/focus checks.
3. The findings, grouped by WCAG criterion, are printed to the terminal
   and (with `--out`) written to `reports/` as four files.
4. Firefox closes.

Options:

- `--out DIR` — write `results.json`, `report.txt`, `report.md`, and
  `report.html` into `DIR`. Without it, only the text summary is printed.
- `--headless` — run Firefox without a visible window. Handy for a quick
  check, but a visible desktop is preferred for accurate focus behavior.

Example (trimmed) output:

```
WCAG 2.2 AA audit
=================
Pages audited (1):
  - https://example.com

Coverage summary
----------------
WCAG 2.2 A + AA criteria in scope: 56
  automatable (full):    10
  automatable (partial): 19
  manual only:           27
Criteria with findings: 3
Findings: 28 error, 0 warning, 45 needs-review

A clean automated run does not imply WCAG 2.2 AA conformance. ...

Findings by criterion
---------------------
1.4.3  Contrast (Minimum)  [AA · full]  — FAIL
  [error] .btn--arrow
      [color-contrast] violation: Elements must meet minimum color contrast ...
```

## What gets checked

Two engines run against the live page and their findings are merged and
grouped by WCAG criterion:

- **axe-core** (run with the AA tag set: `wcag2a`, `wcag2aa`, `wcag21a`,
  `wcag21aa`, `wcag22aa`) for the criteria a machine can decide — colour
  contrast, `lang`, name/role/value, ARIA validity, and more. Its
  "incomplete" results (things axe cannot decide on its own) are surfaced
  as `needs-review`, never as passes.
- **Keyboard / focus checks** that axe deliberately does not perform,
  each emitting `needs-review` candidates for a human to confirm:
  - **2.4.7 / 2.4.11** — is a focus indicator visible; is the focused
    element obscured by other content
  - **2.1.2** — does keyboard focus get trapped
  - **2.4.3** — positive `tabindex` that overrides natural focus order
  - **2.5.8** — interactive targets smaller than 24×24 CSS px

## What the report contains

With `--out DIR`, four views of the same audit are written:

| File | What it holds |
| --- | --- |
| `results.json` | Canonical machine-readable result: every finding with criterion id, severity, message, and selector, plus the coverage summary. The source of truth the other formats render from. |
| `report.html` | Self-contained HTML — open it in any browser. Findings grouped by WCAG criterion, with the coverage summary. |
| `report.md` | The same report as Markdown, for pasting into issues/wikis. |
| `report.txt` | Plain-text report for the terminal. |

Findings carry one of three severities: **error** (a definite failure),
**warning** (a lower-impact definite failure), and **needs-review** (a
candidate the tool flagged but cannot confirm on its own).

## Coverage & honesty

The tool classifies every WCAG 2.2 success criterion into one of three
automatability tiers (the single source of truth is the registry in
`leak_inspector/wcag/core.py`):

- **full** — a tool can decide the automatable substance on its own
  (e.g. colour contrast, `lang`, name/role/value). A machine pass is
  meaningful evidence.
- **partial** — a tool can flag *candidates*, but a human must confirm
  (e.g. link-text quality, reflow, focus order, target size).
- **manual** — needs human judgement; the tool emits only a review item,
  never a pass/fail (e.g. is the alt text *meaningful*, are error
  messages helpful, is the language plain).

Across all **87** criteria: **11 full**, **21 partial**, **55 manual**.
Within the level A + AA conformance target (**56** criteria): **10
full**, **19 partial**, **27 manual** — broadly consistent with the
common estimate that ~30% of WCAG is fully automatable, ~10% partially,
and ~60% needs human review.

Every report states how much of the AA scope is even automatable and
repeats, in plain language, that a clean run is not conformance and that
a criterion with no automated finding is not a pass.

## Roadmap

The intended finished workflow is hand-driven and multi-page:

1. Launch `wcag-checker` on a starting URL; a normal Firefox window opens.
2. Browse the site by hand — click, log in, open menus, dismiss banners.
3. On any page *state* you want audited, press **`Ctrl+Alt+A`**; the tool
   audits the live page and saves a screenshot as evidence.
4. Close the window; a report covering every audited page is written,
   including a manual-review checklist pre-filled per page.

Still to build: the interactive session runner and `Ctrl+Alt+A` hotkey,
the `wcag-checker` console command, per-audit screenshots, and
`manual_checklist.md` generation. Progress is tracked in
[TODO.md](TODO.md).

## Scope / non-goals

- **Not a headless crawler.** Focus and keyboard behavior need a real,
  visible browser on a real desktop.
- **Firefox only.** No Chrome/WebKit driver path.
- **No screen-reader testing.** NVDA/JAWS/VoiceOver announcement behavior
  is out of scope and is directed to the (planned) manual checklist.
- **No content-quality heuristics.** Plain-language and error-helpfulness
  judgements are manual — the tool will not ship a guessy heuristic that
  only produces noise.
- **No always-on monitoring** and **no active remediation.** This tool
  observes and reports; it does not fix pages or run continuously.

## License

GPL-3.0-or-later. See [LICENSE](LICENSE).

This project is a fork of the `leak_inspector` privacy tool, reusing its
Selenium + Firefox + WebDriver BiDi capture core.