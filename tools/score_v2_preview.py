"""Calibrate the Scoring-v2 logistic model against real bundles.

The v2 engine is built but NOT wired into the report yet (roadmap
Phase 6 does the switchover), so `analyze` still prints v1 scores. This
tool runs both so the difference is visible while the model is tuned.

Each v2 dimension's summed penalty is mapped through a logistic S-curve
(both 100 and 0 are asymptotes; steepest in the middle); the three 0–100
dimensions combine by the same cube root the v1 total uses.

    python tools/score_v2_preview.py                 # the calibration set
    python tools/score_v2_preview.py --p50 14 --s 5  # tune the curve
    python tools/score_v2_preview.py captures/foo.zip [more.zip ...]

Scope note: this previews the **module** deductions + per-capture
variants (fully wired). The non-module *signals* (security headers,
cookies, consent, US-ownership) are catalogued but their fact->signal
mapping is Phase-6 work, so they are not yet applied — the v2 numbers
are module-only and will move further once signals land, which is why
p50/s here are provisional.
"""

from __future__ import annotations

import argparse
import glob
import os

from leak_inspector import modules  # noqa: F401  (registers detectors)
from leak_inspector import signals  # noqa: F401  (registers signal ratings)
from leak_inspector.analysis.runner import analyze_bundle
from leak_inspector.modules.base import all_modules
from leak_inspector.report.builder import build_report_document
from leak_inspector.report.score_v2 import (
    DEFAULT_P50,
    DEFAULT_S,
    build_deductions,
    compute_score_logistic,
)

#: The standing calibration set: committed fixtures (clean → busy) plus
#: local working captures. Local-only captures are skipped if absent
#: (the captures/ tree is gitignored), so this runs anywhere.
_CALIBRATION_SET = (
    # committed fixtures
    "tests/fixtures/bundles/brecht.zip",
    "tests/fixtures/bundles/nbb.zip",
    "tests/fixtures/bundles/aalst.zip",
    "tests/fixtures/bundles/kbc.zip",
    "tests/fixtures/bundles/cultuurkuur.zip",
    "tests/fixtures/bundles/doccle-reject.zip",
    "tests/fixtures/bundles/doccle-accept.zip",
    # local working captures (gitignored — skipped if not present)
    "captures/kifkif_max.zip",
    "captures/mijnxtra_min.zip",
    "captures/mijnxtra_max.zip",
)


def preview(path: str, *, p50: float, s: float) -> None:
    analysis = analyze_bundle(path)
    doc = build_report_document(analysis)

    v1 = doc.score
    v1_line = (
        f"R{v1.resilience.stars} S{v1.security.stars} P{v1.privacy.stars}"
        f" = {v1.total}"
        if v1 is not None else "(no score — un-enriched bundle)"
    )

    by_id = {m.module_id: m for m in all_modules()}
    deductions, unrated = build_deductions(analysis, by_id)
    n_mod = sum(1 for d in deductions if d.kind == "module")
    n_sig = sum(1 for d in deductions if d.kind == "signal")
    v2 = compute_score_logistic(deductions, p50=p50, s=s)

    print(f"\n{path.rsplit('/', 1)[-1]}  ({n_mod} modules + {n_sig} signals)")
    print(f"  v1 (report):     {v1_line}")
    print(f"  v2 logistic:     "
          f"R{v2.resilience.score:.0f} S{v2.security.score:.0f} "
          f"P{v2.privacy.score:.0f} = {v2.total:.0f}")
    print(f"  v2 penalty:      "
          f"R{v2.resilience.penalty:g} S{v2.security.penalty:g} "
          f"P{v2.privacy.penalty:g}")
    top = [d for d in sorted(deductions, key=lambda d: -d.rating.privacy)
           if d.rating.privacy > 0][:6]
    if top:
        print("  top privacy hits: "
              + ", ".join(f"{d.label} -{d.rating.privacy:g}" for d in top))
    if unrated:
        print(f"  unrated modules:  {', '.join(unrated)}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="*", help="bundle paths or globs")
    parser.add_argument("--p50", type=float, default=DEFAULT_P50,
                        help=f"penalty scoring 50 (default {DEFAULT_P50})")
    parser.add_argument("--s", type=float, default=DEFAULT_S,
                        help=f"curve steepness (default {DEFAULT_S})")
    args = parser.parse_args()

    if args.paths:
        paths = [p for pattern in args.paths for p in glob.glob(pattern)]
    else:
        paths = [p for p in _CALIBRATION_SET if os.path.exists(p)]

    anchor = compute_score_logistic([], p50=args.p50, s=args.s)
    print(f"logistic curve: p50={args.p50:g} s={args.s:g}  "
          f"(penalty-free dimension scores {anchor.privacy.score:.1f})")
    for path in paths:
        try:
            preview(path, p50=args.p50, s=args.s)
        except Exception as exc:  # noqa: BLE001 -- best-effort preview
            print(f"\n{path}: ERROR {type(exc).__name__}: {exc}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
