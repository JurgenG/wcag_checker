# WCAG 2.2 coverage

This document explains, per WCAG 2.2 success criterion, how much
`wcag-checker` decides automatically and how much is left to a person.
The authoritative source is `CRITERIA_REGISTRY` in
[`leak_inspector/wcag/core.py`](../leak_inspector/wcag/core.py).

Automated checks find machine-detectable defects. Whether content makes
sense to a person using assistive technology is judged by a reviewer,
using the manual checklist and review pointers in every report. A WCAG
2.2 AA conformance claim combines both.

## The three tiers

Each of the 86 WCAG 2.2 success criteria has one tier:

| Tier | Meaning | What the report contains |
|--- |--- |--- |
| **full** | The tool decides the automatable part of the criterion. | Pass/fail findings. No finding means the automatable part found no defect. |
| **partial** | The tool flags candidates; a person confirms. | `needs-review` findings and a checklist item. |
| **manual** | A person decides. | A checklist item, plus review pointers for some criteria. |

A criterion is tiered `full` only when the engine fully decides its
automatable part.

## Distribution

| Tier | All 86 criteria | Level A + AA (55) |
|--- |--- |--- |
| full | 10 | 9 |
| partial | 24 | 22 |
| manual | 52 | 24 |

## Where the findings come from

### axe-core (`axe_runner.py`)

[axe-core](https://github.com/dequelabs/axe-core) runs with the WCAG
2.0 / 2.1 / 2.2 A and AA rule tags. It decides the `full` criteria and
contributes to many `partial` ones, for example:

- **1.1.1 Non-text Content** — images and controls have a text
  alternative (a person judges whether it is meaningful).
- **1.3.1 Info and Relationships** — table headers, list structure, ARIA
  relationships.
- **1.4.3 / 1.4.6 Contrast** — text colour-contrast ratios.
- **1.3.4 Orientation**, **1.3.5 Identify Input Purpose**, **2.4.1 Bypass
  Blocks**, **2.4.2 Page Titled**, **3.1.1 Language of Page**, **3.1.2
  Language of Parts**.
- **4.1.2 Name, Role, Value** — valid ARIA roles and attributes,
  accessible names for controls.
- **1.2.2 Captions** for native video (`video-caption`), **1.4.2 Audio
  Control** (`no-autoplay-audio`), **2.2.1 Timing Adjustable**
  (`meta-refresh`), **2.2.2 Pause, Stop, Hide** (`marquee`, `blink`).
- **2.5.3 Label in Name** — the `label-content-name-mismatch` rule,
  reported as `needs-review`.

Checks that axe-core cannot finish (its *incomplete* results) are
reported as `needs-review`.

### Keyboard and focus (`keyboard_nav.py`)

These checks operate the page with the keyboard and measure the result:

- **2.4.7 Focus Visible / 2.4.11 Focus Not Obscured** — each focusable
  element shows a visible focus indicator and is not hidden when
  focused.
- **2.1.2 No Keyboard Trap** — focus can move away from every element.
- **2.4.3 Focus Order** — positive `tabindex` values that override the
  natural order.
- **2.5.8 Target Size (Minimum)** — interactive targets of at least
  24×24 CSS px, or with enough spacing.

All are `partial`: a person confirms each candidate.

### Media (`media.py`)

All `needs-review`, each with a screenshot:

- **1.2.1** — native `<audio>`: confirm a transcript exists. Other
  embedded frames: classify whether they contain media.
- **1.2.3** — native `<video>`: confirm an audio description or text
  alternative exists. The finding lists the caption, subtitle and
  description tracks found.
- **1.2.2 + 1.2.3** — YouTube and Vimeo embeds: check captions and audio
  description in the player itself.

### Review pointers (`pointers.py`)

For these `manual` criteria the report points at the exact elements to
review, with screenshots:

- **4.1.3 Status Messages** — ARIA live regions.
- **3.3.8 Accessible Authentication (Minimum)** — password fields and
  CAPTCHA widgets.
- **2.4.5 Multiple Ways** — search forms, navigation and sitemap links.
- **3.2.6 Consistent Help** — help and contact links.

### Descriptive text (`content.py`)

- **2.4.4 Link Purpose** — links with generic text such as "click here"
  or "read more".
- **2.4.6 Headings and Labels** — headings without text.

Both `needs-review`.

### Reflow (`reflow.py`)

- **1.4.10 Reflow** — sets a 320 CSS-px wide viewport and flags
  horizontal scrolling as `needs-review`.

### Manual checklist (`manual_checklist.py`)

Every `manual` criterion, and the confirmation step of every `partial`
criterion, appears in the checklist with concrete review questions for
each audited page. It covers, among others:

- meaningful alt text and link text in context;
- whether media alternatives exist and are adequate, including live
  captions (1.2.4) and audio description (1.2.5);
- error identification, suggestions and prevention (3.3.1–3.3.4) and
  status messages (4.1.3);
- sensory characteristics (1.3.3), use of colour (1.4.1), content on
  hover or focus (1.4.13);
- full keyboard operability (2.1.1) and pointer, gesture and motion
  criteria (2.5.1, 2.5.2, 2.5.4, 2.5.7);
- plain language and other cognitive criteria.

## Criteria by tier

**full (10):** 1.1.1, 1.3.1, 1.3.4, 1.3.5, 1.4.3, 1.4.6, 2.4.1, 2.4.2,
3.1.1, 4.1.2

**partial (24):** 1.2.1, 1.2.2, 1.2.3, 1.3.2, 1.4.1, 1.4.2, 1.4.4,
1.4.10, 1.4.11, 1.4.12, 2.1.2, 2.2.1, 2.2.2, 2.4.3, 2.4.4, 2.4.6, 2.4.7,
2.4.9, 2.4.11, 2.5.3, 2.5.5, 2.5.8, 3.1.2, 3.3.2

**manual (52):** every other criterion.

## Interpreting a clean run

Zero errors means the machine-checkable defects the tool detects were
not found on the audited pages. Together with a completed manual
checklist, reviewed with real assistive technology, it supports a WCAG
2.2 AA conformance claim.
