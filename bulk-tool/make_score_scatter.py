"""Build an interactive 3D scatter of bulk-scan scores.

Reads every ``<dataset>/reports/*.report.json`` and emits an HTML file
plotting each scanned site as one point whose (x, y, z) are the three
scoring domains — privacy, security and resilience. The plot is
rotatable/zoomable with the mouse (Plotly WebGL scatter3d). Points are
coloured by their combined total score.

The HTML references ``plotly.min.js`` from its own directory; the
script places a copy there (downloading it once if absent) so the chart
works offline.

Usage:
    python3 bulk-tool/make_score_scatter.py <dataset_dir> [-o OUT.html]

``<dataset_dir>`` must contain a ``reports/`` folder with the JSON
reports produced by the bulk runner.
"""
from __future__ import annotations

import argparse
import glob
import json
import os
from pathlib import Path

AXES = ("privacy", "security", "resilience")
PLOTLY_URL = "https://cdn.plot.ly/plotly-2.35.2.min.js"


def ensure_plotly(dest_dir: Path) -> None:
    """Ensure ``plotly.min.js`` exists in ``dest_dir`` (download once)."""
    target = dest_dir / "plotly.min.js"
    if target.is_file() and target.stat().st_size > 1_000_000:
        return
    import urllib.request

    with urllib.request.urlopen(PLOTLY_URL, timeout=60) as resp:
        target.write_bytes(resp.read())
    print(f"fetched plotly.min.js -> {target}")


def collect(reports_dir: Path) -> list[dict]:
    """Return one record per scored report: coords, label and total."""
    points: list[dict] = []
    for f in sorted(glob.glob(str(reports_dir / "*.report.json"))):
        try:
            d = json.load(open(f, encoding="utf-8"))
        except (ValueError, OSError):
            continue
        score = d.get("score") or {}
        if not all(a in score for a in AXES):
            continue
        try:
            coords = {a: float(score[a]["raw_score"]) for a in AXES}
            stars = {a: int(score[a]["stars"]) for a in AXES}
        except (KeyError, TypeError, ValueError):
            continue
        label = (
            (d.get("manifest") or {}).get("base_domain")
            or os.path.basename(f).replace(".report.json", "")
        )
        points.append({
            "label": label,
            "x": round(coords["privacy"], 2),
            "y": round(coords["security"], 2),
            "z": round(coords["resilience"], 2),
            "stars": stars,
            "total": score.get("total"),
        })
    return points


def render(points: list[dict], dataset_name: str) -> str:
    """Return a self-contained HTML document for the given points."""
    data_json = json.dumps(points, ensure_ascii=False)
    title = f"Leak Inspector — score landscape ({dataset_name}, n={len(points)})"
    # Template kept brace-free except the two %s slots filled below.
    return _TEMPLATE.replace("__TITLE__", title).replace("__DATA__", data_json)


_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>__TITLE__</title>
<script src="plotly.min.js" charset="utf-8"></script>
<style>
  html,body{margin:0;height:100%;background:#0f1115;color:#e6e6e6;
    font-family:system-ui,Segoe UI,Roboto,sans-serif}
  #plot{width:100vw;height:100vh}
  #cap{position:fixed;left:12px;top:10px;z-index:10;font-size:13px;
    line-height:1.4;background:rgba(15,17,21,.7);padding:8px 12px;
    border-radius:8px;max-width:46ch}
  #cap b{color:#fff}
  #cap span{color:#9aa}
</style>
</head>
<body>
<div id="cap"><b>__TITLE__</b><br>
<span>Each point is one scanned site. Axes = privacy / security /
resilience raw scores (0&ndash;100). Drag to rotate, scroll to zoom,
hover for the site. Colour = combined total.</span></div>
<div id="plot"></div>
<script>
const PTS = __DATA__;
const hov = PTS.map(p =>
  p.label + "<br>privacy " + p.stars.privacy +
  " | security " + p.stars.security +
  " | resilience " + p.stars.resilience +
  (p.total!=null ? "<br>total " + p.total : ""));
const trace = {
  type:"scatter3d", mode:"markers",
  x:PTS.map(p=>p.x), y:PTS.map(p=>p.y), z:PTS.map(p=>p.z),
  text:hov, hoverinfo:"text",
  marker:{
    size:3.2, opacity:0.78,
    color:PTS.map(p=> p.total!=null ? p.total : (p.x+p.y+p.z)/3),
    colorscale:"Viridis", showscale:true,
    colorbar:{title:"total", tickfont:{color:"#ccc"},
      titlefont:{color:"#ccc"}},
    line:{width:0}
  }
};
const ax = t => ({title:t, range:[0,100], gridcolor:"#333",
  zerolinecolor:"#555", color:"#bbb", backgroundcolor:"#0f1115",
  showbackground:true});
Plotly.newPlot("plot", [trace], {
  paper_bgcolor:"#0f1115",
  margin:{l:0,r:0,t:0,b:0},
  scene:{
    xaxis:ax("privacy"), yaxis:ax("security"), zaxis:ax("resilience"),
    aspectmode:"cube",
    camera:{eye:{x:1.5,y:1.5,z:1.2}}
  }
}, {responsive:true, displaylogo:false});
</script>
</body>
</html>
"""


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("dataset_dir", type=Path,
                    help="dataset folder containing reports/")
    ap.add_argument("-o", "--out", type=Path, default=None,
                    help="output HTML path (default <dataset>/score_scatter.html)")
    args = ap.parse_args()

    reports_dir = args.dataset_dir / "reports"
    if not reports_dir.is_dir():
        ap.error(f"no reports/ folder in {args.dataset_dir}")

    points = collect(reports_dir)
    if not points:
        ap.error(f"no scored reports found in {reports_dir}")

    out = args.out or (args.dataset_dir / "score_scatter.html")
    out.write_text(render(points, args.dataset_dir.name), encoding="utf-8")
    ensure_plotly(out.parent)
    print(f"{len(points)} points -> {out}")


if __name__ == "__main__":
    main()
