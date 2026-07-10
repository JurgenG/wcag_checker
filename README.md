# wcag-checker

Audit a live, browser-rendered web page for WCAG 2.2 AA conformance.
`wcag-checker` drives a real Firefox and runs its checks against the DOM
as rendered, including client-side content and state reached by
interaction (e.g. after dismissing a consent banner).

A clean run is not a conformance claim: automated tooling decides only
part of a subset of the success criteria (see [Coverage](#coverage)).

## Requirements

- Python 3.12+
- Firefox. geckodriver is fetched automatically by Selenium; if Firefox
  is missing, a private copy is downloaded on first run.
- A visible desktop for the interactive and default runs — the
  keyboard/focus checks move focus and measure the rendered page.
  `--headless` runs without a window, but those checks are less reliable.

## Install

See [INSTALL.md](INSTALL.md) for a step-by-step guide. Short version:

```bash
git clone <your-repository-url> wcag-checker
cd wcag-checker
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate.bat
pip install -e .
```

## Usage

Three modes, all writing the same per-page report set.

### Interactive (`wcag-checker`)

```bash
wcag-checker https://example.com --out reports/
```

1. Firefox opens on the URL. Browse normally.
2. Click into the page (so it has keyboard focus), then press
   `Ctrl+Alt+Shift+A` to audit its current rendered state (axe-core +
   keyboard/focus checks). Each audit is confirmed on the console. Repeat
   on as many pages as needed.
3. Close the window. Reports for every audited page are written to
   `reports/`.

Options: `--out DIR` (default `reports/`), `--headless`, and `--hotkey
COMBO` (default `ctrl+alt+shift+a`) — change it if your window manager
grabs the default, e.g. `--hotkey f9` or `--hotkey ctrl+alt+shift+w`.

### One-shot (`wcag-checker --once`)

```bash
wcag-checker https://example.com --once --out reports/
```

Opens Firefox, waits for the page to settle (so a client-side redirect
does not race the audit), audits that page, writes the reports, and
exits. If the page redirects, the settled URL is audited and reported.

Options: `--out DIR` (default `reports/`), `--headless`.

### Batch (`wcag-batch`)

```bash
wcag-batch urls.txt --out runs/
wcag-batch bulk-tool/datasets/publiq/domains.csv --out runs/ --limit 20
```

Audits every URL in a list (one per line; `#` comments and blank lines
ignored), reusing one Firefox. Each site is audited into `runs/<site>/`
with the full report set. A site that fails (DNS error, timeout, …) is
recorded and the run continues. `runs/summary.{json,md,html}` has one row
per site — findings by severity or the failure — linking to each report.

Options: `--out DIR` (default `runs/`), `--limit N`, `--headless`.
Example URL lists are in `bulk-tool/datasets/`.

## What gets checked

Two engines run against the live page; findings are merged and grouped by
WCAG criterion:

- **axe-core**, with the AA tag set (`wcag2a`, `wcag2aa`, `wcag21a`,
  `wcag21aa`, `wcag22aa`): colour contrast, `lang`, name/role/value, ARIA
  validity, and more. axe "incomplete" results are reported as
  `needs-review`, not as passes.
- **Keyboard/focus checks** axe does not perform, each reported as
  `needs-review`:
  - 2.4.7 / 2.4.11 — focus indicator visible; focused element not obscured
  - 2.1.2 — keyboard focus trap
  - 2.4.3 — positive `tabindex` overriding focus order
  - 2.5.8 — targets smaller than 24×24 CSS px

## Output

Each run writes to the output directory (`--out`, default `reports/`):

| File | Contents |
| --- | --- |
| `results.json` | Machine-readable result: each finding (criterion id, severity, message, selector, screenshot path) plus the coverage summary. Source of truth for the other formats. |
| `report.html` | HTML report (inline styling); findings grouped by criterion, each with a screenshot thumbnail. |
| `report.md` | Markdown report. |
| `report.txt` | Plain-text report. |
| `manual-checklist.md` | Review checklist: the 46 A + AA criteria tooling cannot decide, each with step-by-step questions, per audited page. |
| `screenshots/` | One PNG per flagged element (one shot per element, reused across criteria). Findings reference these by relative path. |

`wcag-batch` additionally writes `summary.{json,md,html}` at the top
level and one subdirectory per site.

Severities: **error** (definite failure), **warning** (lower-impact
definite failure), **needs-review** (unconfirmed candidate).

## Coverage

Each WCAG 2.2 success criterion is classified by how much a tool can
decide (registry: `leak_inspector/wcag/core.py`):

- **full** — the automatable substance can be decided by the tool (e.g.
  colour contrast, `lang`, name/role/value).
- **partial** — the tool flags candidates; a human confirms (e.g.
  link-text quality, reflow, focus order, target size).
- **manual** — needs human judgement; the tool emits only a review item
  (e.g. meaningfulness of alt text, error-message quality, plain
  language).

All 87 criteria: 11 full, 21 partial, 55 manual. Level A + AA scope (56
criteria): 10 full, 19 partial, 27 manual. A criterion with no automated
finding is not a pass; every criterion needs manual review before a
conformance claim.

## Scope / non-goals

- Not a headless crawler; focus/keyboard checks need a visible browser.
- Firefox only. No Chrome/WebKit driver.
- No screen-reader (NVDA/JAWS/VoiceOver) testing; directed to the manual
  checklist.
- No content-quality heuristics (plain language, error-message quality);
  these are manual.
- No monitoring or remediation; it observes and reports.

## License

GPL-3.0-or-later. See [LICENSE](LICENSE).

Fork of the `leak_inspector` privacy tool, reusing its Selenium + Firefox
+ WebDriver BiDi capture core.
