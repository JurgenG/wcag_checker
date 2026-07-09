# WCAG 2.2 automatability coverage

This document is the human-readable companion to the criteria registry
in [`leak_inspector/wcag/core.py`](../leak_inspector/wcag/core.py),
which is the authoritative source. It explains **how much of each WCAG
2.2 success criterion this tool can decide on its own**, and — just as
importantly — how much it cannot.

> **Read this first.** A clean automated run is **not** WCAG
> conformance. Automated tooling can confirm the *absence* of certain
> machine-detectable defects; it cannot confirm the *presence* of
> accessibility. Most of WCAG is about whether content makes sense to a
> human using assistive technology, and only a person can judge that.

## The three tiers

Every one of the 87 WCAG 2.2 success criteria is tagged with exactly one
automatability tier:

| Tier | Meaning | What the tool emits |
|--- |--- |--- |
| **full** | A tool can decide the automatable substance of the criterion on its own. | Pass/fail findings; a clean result is meaningful evidence (for the automatable part). |
| **partial** | A tool can flag *candidates*, but a human must confirm. | `needs-review` findings + a checklist item. |
| **manual** | Needs human judgement; no machine decision is possible. | A checklist item only — never a pass/fail. |

Tiering here is deliberately **conservative**: when a criterion is only
shallowly checkable, it is marked `partial` or `manual` rather than
`full`. A false green is worse than an honest "needs review".

## Distribution

Derived from the registry (`CRITERIA_REGISTRY` in `core.py`):

| Tier | Count | Share |
|--- |--- |--- |
| full | 11 | ~13% |
| partial | 21 | ~24% |
| manual | 55 | ~63% |
| **total** | **87** | 100% |

This is broadly consistent with the widely-cited industry estimate that
roughly 30% of WCAG is fully automatable, ~10% partially, and ~60%
requires human judgement. This tool lands lower on "full" because it
only claims `full` where the engine genuinely decides the criterion.

## Where the coverage comes from

Three sources produce findings; everything else is checklist-only.

### axe-core (via `axe_runner.py`)

The [axe-core](https://github.com/dequelabs/axe-core) engine (bundled by
`axe-selenium-python`, run with the WCAG 2.2 AA rule tags) drives the
`full`-tier criteria and many `partial` ones. It reliably decides
things like:

- **1.1.1 Non-text Content** — presence of `alt` / accessible names on
  images (not whether the text is *meaningful*).
- **1.3.1 Info and Relationships** — table headers, list structure, ARIA
  relationships.
- **1.4.3 / 1.4.6 Contrast** — text colour-contrast ratios.
- **1.3.4 Orientation**, **1.3.5 Identify Input Purpose**
  (autocomplete validity), **2.4.1 Bypass Blocks**, **2.4.2 Page
  Titled**, **3.1.1 Language of Page**.
- **4.1.1 Parsing** (duplicate ids), **4.1.2 Name, Role, Value** — ARIA
  attribute/role validity, accessible names for controls.

axe-core also returns *incomplete* results — checks it could not fully
decide. Those are surfaced as `needs-review` findings, not passes.

### Keyboard / focus checks (via `keyboard_nav.py`)

axe-core deliberately does **not** test focus and keyboard flow, because
they require actually operating the page. This tool adds custom checks
for the automatable slice of:

- **2.4.7 / 2.4.11 Focus Visible / Not Obscured** — is a visible focus
  indicator present when each element is focused.
- **2.1.2 No Keyboard Trap** — can focus move away from every element
  via the keyboard.
- **2.4.3 Focus Order** — does DOM/tab order track visual order.
- **2.5.8 Target Size (Minimum)** — are interactive targets at least
  24×24 CSS px (or adequately spaced).

These are `partial`: they catch concrete defects but cannot certify the
criterion (e.g. a logical-but-unusual focus order can be correct).

### The manual checklist (via `manual_checklist.py`)

The `manual`-tier majority — and the human-confirmation half of every
`partial` criterion — is emitted as a checklist, pre-filled with the
pages that were audited. These are criteria no tool should pretend to
decide, including:

- Meaningful (vs merely present) alt text and link text in context.
- Media alternatives: captions, audio description, transcripts
  (1.2.x).
- Error-message quality and prevention (3.3.1–3.3.4).
- Plain language / reading level (3.1.5) and other cognitive criteria.
- Sensory characteristics (1.3.3), use of colour intent (1.4.1),
  content on hover/focus (1.4.13).
- Full keyboard operability (2.1.1) and all pointer/gesture/motion
  criteria (2.5.1, 2.5.2, 2.5.4, 2.5.7).
- All AAA content-quality criteria.

## Full mapping

The complete per-criterion tier list is the `CRITERIA_REGISTRY` tuple in
[`core.py`](../leak_inspector/wcag/core.py). For reference, the
non-`manual` criteria are:

**full (11):** 1.1.1, 1.3.1, 1.3.4, 1.3.5, 1.4.3, 1.4.6, 2.4.1, 2.4.2,
3.1.1, 4.1.1, 4.1.2

**partial (21):** 1.3.2, 1.4.1, 1.4.4, 1.4.10, 1.4.11, 1.4.12, 2.1.2,
2.2.1, 2.2.2, 2.4.3, 2.4.4, 2.4.6, 2.4.7, 2.4.9, 2.4.11, 2.5.3, 2.5.5,
2.5.8, 3.1.2, 3.3.2, 4.1.3

Every remaining criterion (**55**) is `manual`.

## The bottom line

If this tool reports zero errors, it means: *the machine-checkable
defects it knows how to detect were not present on the pages you
audited.* It does not mean the site is accessible, and it does not mean
the site conforms to WCAG 2.2 AA. Conformance still requires working
through the manual checklist with real assistive technology and real
human judgement.