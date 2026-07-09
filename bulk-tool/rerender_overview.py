"""Overview-only re-render: rebuild a dataset's index.html from the
existing capture bundles (offline analyze_bundle — no capture, no
network, no browser). Usage: python rerender_overview.py <dataset>"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from overview import build_overview  # noqa: E402

name = sys.argv[1]
dataset = ROOT / "datasets" / name
idx = build_overview(dataset)
if idx is None:
    print(f"{name}: no index written", file=sys.stderr)
    sys.exit(1)
html = Path(idx).read_text(encoding="utf-8")
charts = html.count('class="score-hist"')
print(f"RESULT {name}: score-hist charts={charts}  index={idx}")
