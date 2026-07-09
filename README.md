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
| Manual-review checklist for the criteria tooling can't decide, with step-by-step review questions per criterion | ✅ working |
| One-shot single-page audit (`wcag-checker --once`) | ✅ working |
| Interactive **hotkey** session (browse by hand, press `Ctrl+Alt+A` per page) | ✅ working |
| `wcag-checker` console command | ✅ working |
| Per-finding screenshots (a PNG of each flagged element as evidence) | ✅ working |

The hand-driven, multi-page workflow — browse, press `Ctrl+Alt+A` on each
page, close the window to get a report — works via the `wcag-checker`
command (below), and every finding is now saved with a screenshot of the
offending element as evidence. What remains is the packaging pass.

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
pip install -e .                   # pulls in the axe-core engine too
```

## Usage

### Interactive session (`wcag-checker`)

Browse by hand and audit each page you choose:

```bash
wcag-checker https://example.com --out reports/
```

What happens:

1. A visible Firefox window opens on the URL. Browse normally — click,
   log in, open menus, dismiss banners.
2. On any page (or page *state*) you want checked, press **`Ctrl+Alt+A`**.
   The tool audits the DOM **as rendered at that instant** — axe-core's
   WCAG 2.2 AA rules plus the keyboard/focus checks — accumulates the
   findings, and saves a PNG of each flagged element (the snippet with the
   issue) to `reports/screenshots/`. Press it on as many pages as you like.
3. **Close the Firefox window.** The reports for every audited page are
   written to `reports/`.

Options: `--out DIR` (default `reports/`) and `--headless` (a visible
desktop is preferred for accurate focus behaviour).

### One-shot audit (`--once`)

For a quick, non-interactive check of a single page — no hotkey:

```bash
wcag-checker https://example.com --once --out reports/
```

It opens Firefox, **waits for the page to settle** (so a client-side
redirect can't race the audit), audits that one rendered page, writes the
reports, and exits. This is the right mode for a page that redirects or
vanishes too fast to press `Ctrl+Alt+A` by hand; if a redirect happens it
audits — and reports — the URL the page settled on. Same `--out` and
`--headless` options.

Example (trimmed) output from an audit:

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

With `--out DIR`, four views of the same audit are written, plus a
`screenshots/` directory of evidence:

| File | What it holds |
| --- | --- |
| `results.json` | Canonical machine-readable result: every finding with criterion id, severity, message, selector, and the path to its element screenshot, plus the coverage summary. The source of truth the other formats render from. |
| `report.html` | HTML with inline styling — open it in any browser. Findings grouped by WCAG criterion, each with a thumbnail of the offending element, and the coverage summary. |
| `report.md` | The same report as Markdown, for pasting into issues/wikis. |
| `report.txt` | Plain-text report for the terminal. |
| `manual-checklist.md` | The human-review checklist: the 46 A + AA criteria tooling cannot decide, each with step-by-step review questions as checkboxes, grouped per audited page. |
| `screenshots/` | One PNG per flagged element (the snippet with the issue), named so an element failing several criteria is captured once. Findings reference these by relative path. |

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

The hand-driven, multi-page workflow (`wcag-checker` → browse → press
`Ctrl+Alt+A` per page → close the window → report), with per-finding
element screenshots, is in place, and `axe-selenium-python` now installs
with the package. What remains is internal cleanup of privacy-tool
leftovers still in the tree (see [TODO.md](TODO.md)).

## Scope / non-goals

- **Not a headless crawler.** Focus and keyboard behavior need a real,
  visible browser on a real desktop.
- **Firefox only.** No Chrome/WebKit driver path.
- **No screen-reader testing.** NVDA/JAWS/VoiceOver announcement behavior
  is out of scope and is directed to the manual checklist.
- **No content-quality heuristics.** Plain-language and error-helpfulness
  judgements are manual — the tool will not ship a guessy heuristic that
  only produces noise.
- **No always-on monitoring** and **no active remediation.** This tool
  observes and reports; it does not fix pages or run continuously.

## License

GPL-3.0-or-later. See [LICENSE](LICENSE).

This project is a fork of the `leak_inspector` privacy tool, reusing its
Selenium + Firefox + WebDriver BiDi capture core.