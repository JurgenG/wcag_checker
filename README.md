# wcag-checker

Record a real, human-driven browsing session in Firefox and audit the
pages you visit for **WCAG 2.2 AA** accessibility conformance — against
the *live, fully-rendered* page, the way a real visitor actually
experiences it.

Most accessibility scanners crawl a URL and audit whatever the server
returns. That misses everything behind interaction: content revealed by
a click, state after a consent banner is dismissed, views built entirely
in the browser. `wcag-checker` takes the opposite approach — **you**
drive Firefox by hand, and when a page is in the state you want checked,
you press a hotkey and the audit runs on the DOM as it stands at that
instant.

> **Honest by design.** WCAG 2.2 has 87 success criteria. Only a
> minority can be decided by a machine; most require human judgement.
> A clean run from this tool is **not** a statement of WCAG conformance
> — it means the *automatable* checks found no defect. See
> [Coverage & honesty](#coverage--honesty).

## How it works

1. You launch the tool on a starting URL. A normal, visible Firefox
   window opens.
2. You browse the site by hand — click, log in, open menus, dismiss
   banners — exactly as a visitor would.
3. On any page (or page *state*) you want audited, you press the **audit
   hotkey**: `Ctrl+Alt+A` (`Ctrl+Option+A` on macOS). The tool audits
   the live page right then and saves a screenshot as evidence. Press it
   as many times as you like across as many pages as you like.
4. You close the Firefox window. The tool writes a report covering every
   page you audited.

The audit itself combines three things:

- **axe-core** (the industry-standard accessibility engine, run with the
  WCAG 2.2 AA rule tags) for the criteria a machine can decide —
  contrast, `lang`, name/role/value, ARIA validity, and more.
- **Keyboard / focus checks** that axe-core deliberately does not
  perform: is focus visible, is there a keyboard trap, does focus order
  match visual order, are interactive targets large enough.
- **A manual-review checklist** listing the criteria no tool can decide
  for you, pre-filled with the pages you visited so a human reviewer
  knows exactly what still needs eyes.

## Quickstart

Install (see [INSTALL.md](INSTALL.md) for a step-by-step, zero-experience
guide covering Windows, macOS, and Linux):

```bash
git clone <your-repository-url> wcag-checker
cd wcag-checker
python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate.bat
pip install -e .
```

You need Python **3.12+**, a real desktop (not a headless server), and
Firefox — geckodriver is fetched automatically by Selenium.

Run an audit:

```bash
wcag-checker https://example.com --out reports/
```

A Firefox window opens on `example.com`. Browse to whatever you want to
check, press **`Ctrl+Alt+A`** on each page, then **close the window**.
The report lands in `reports/`.

Reuse an existing Firefox profile (to test while logged in, with your
own cookies/extensions) — note the profile is used in place and will be
modified:

```bash
wcag-checker https://example.com --out reports/ --profile ~/path/to/profile
```

## What the report contains

Everything is written into the `--out` directory:

| File | What it holds |
|--- |--- |
| `results.json` | Canonical machine-readable result: every finding, per page, with criterion id, severity, message, and selector. The source of truth other formats render from. |
| `report.html` | Self-contained HTML report — open it in any browser. Findings grouped by WCAG criterion, with the coverage summary and screenshots. |
| `report.md` | The same report as Markdown, for pasting into issues/wikis. |
| `report.txt` | Plain-text report for the terminal. |
| `manual-checklist.md` | The human-review checklist: the criteria that can't be automated, per audited page, ready to work through. |
| `*.png` | One screenshot per audit press, as visual evidence of the state that was checked. |

Findings carry one of three severities: **error** (a definite failure),
**warning** (a lower-impact definite failure), and **needs-review** (a
candidate the tool flagged but cannot confirm on its own).

## Coverage & honesty

The tool classifies every WCAG 2.2 success criterion into one of three
automatability tiers (the full mapping lives in
[`docs/COVERAGE.md`](docs/COVERAGE.md) and is derived from the registry
in `leak_inspector/wcag/core.py`):

- **full** — a tool can decide the automatable substance on its own
  (e.g. colour contrast, `lang`, name/role/value). A machine pass is
  meaningful evidence.
- **partial** — a tool can flag *candidates*, but a human must confirm
  (e.g. link-text quality, reflow, focus order, target size).
- **manual** — needs human judgement; the tool emits only a checklist
  item, never a pass/fail (e.g. is the alt text *meaningful*, are error
  messages helpful, is the language plain).

In this tool's conservative tiering, **11 of 87** criteria are `full`,
**21** are `partial`, and **55** are `manual` — broadly consistent with
the commonly-cited estimate that ~30% of WCAG is fully automatable, ~10%
partially, and ~60% needs human review.

The report **always** states how many criteria were actually exercised
and repeats, plainly, that a clean automated run does not imply
conformance. Green never means done.

## Scope / non-goals

- **Not headless.** Focus and keyboard behavior need a real, visible
  browser on a real desktop. There is no scripted/headless crawl mode.
- **Firefox only.** No Chrome/WebKit driver path.
- **No screen-reader testing.** NVDA/JAWS/VoiceOver announcement
  behavior is out of scope and is directed to the manual checklist.
- **No content-quality heuristics.** Plain-language and
  error-helpfulness judgements are manual — the tool will not ship a
  guessy heuristic that only produces noise.
- **No always-on monitoring** and **no active remediation.** This tool
  observes and reports; it does not fix pages or run continuously.

## License

GPL-3.0-or-later. See [LICENSE](LICENSE).

This project is a fork of the `leak_inspector` privacy tool, reusing its
Selenium + Firefox + WebDriver BiDi capture core.