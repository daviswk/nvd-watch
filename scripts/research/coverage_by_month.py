"""coverage_by_month.py — does CPE coverage fill in as a cohort ages? (S6: a proposed brief figure)

Question: the page's 22% CPE share is for CVEs at most 30 days old. For older monthly cohorts (by NVD
publication month, Jan 2024 – Oct 2026), what share has CPE now, and what share is Not Scheduled now?
If old pre-triage cohorts sit near 100% and post-triage cohorts plateau well below it, the gap is not
just a young-window artefact (pushback point 10). One snapshot of current status; it shows where each
cohort is today, not how it got there.

Inputs:  NVD JSON 2.0 yearly feeds (same as recheck_volume.py); CISA KEV JSON
Outputs: data/processed/coverage_by_month.json, data/processed/coverage_by_month.svg (rough chart)
Run:     python -I scripts/research/coverage_by_month.py NVD_DIR KEV_JSON
"""
import json
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from recheck_volume import load_nvd  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]


def main(nvd_dir, kev_json):
    nvd = load_nvd(nvd_dir)
    kev = {v["cveID"] for v in json.load(open(kev_json, encoding="utf-8"))["vulnerabilities"]}
    by = defaultdict(lambda: {"n": 0, "cpe": 0, "deferred": 0, "kev": 0, "kev_cpe": 0})
    for c, v in nvd.items():
        m = f"{v['pub'].year}-{v['pub'].month:02d}"
        if v["status"] == "Rejected" or not ("2024-01" <= m <= "2026-10"):
            continue
        b = by[m]
        b["n"] += 1
        b["cpe"] += v["has_cpe"]
        b["deferred"] += v["status"] == "Deferred"
        if c in kev:
            b["kev"] += 1
            b["kev_cpe"] += v["has_cpe"]
    rows = [{"month": m, **b, "pct_cpe": round(100 * b["cpe"] / b["n"], 1),
             "pct_not_scheduled": round(100 * b["deferred"] / b["n"], 1)} for m, b in sorted(by.items())]
    for r in rows:
        print(r["month"], r["n"], f"{r['pct_cpe']}% CPE", f"{r['pct_not_scheduled']}% Not Scheduled",
              f"KEV {r['kev_cpe']}/{r['kev']}")
    out = {"about": __doc__.split("\n\n")[0], "snapshot": "NVD yearly feeds downloaded 2026-11-08",
           "triage_start": "2026-04-15", "rows": rows}
    (ROOT / "data" / "processed" / "coverage_by_month.json").write_text(json.dumps(out, indent=1))

    # Rough SVG: bars = % with CPE now; line marks = % Not Scheduled now.
    w, h, left, top, bw = 760, 300, 40, 20, 20
    parts = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h + 60}" font-family="sans-serif" font-size="10">',
             f'<text x="{left}" y="12" font-size="12">Share of CVEs with CPE now (bars) and Not Scheduled now (dots), '
             'by NVD publication month. Snapshot Nov 8, 2026.</text>']
    for pct in (0, 25, 50, 75, 100):
        y = top + h - h * pct / 100
        parts.append(f'<line x1="{left}" x2="{w}" y1="{y}" y2="{y}" stroke="#ddd"/><text x="5" y="{y + 3}">{pct}%</text>')
    for i, r in enumerate(rows):
        x = left + 5 + i * (bw + 1.5)
        bh = h * r["pct_cpe"] / 100
        fill = "#1d4e5f" if r["month"] < "2026-04" else "#7fa6b3"
        parts.append(f'<rect x="{x}" y="{top + h - bh}" width="{bw}" height="{bh}" fill="{fill}"/>')
        parts.append(f'<circle cx="{x + bw / 2}" cy="{top + h - h * r["pct_not_scheduled"] / 100}" r="3" fill="#b5462e"/>')
        if r["month"].endswith(("01", "04", "07", "10")):
            parts.append(f'<text x="{x}" y="{top + h + 14}">{r["month"]}</text>')
    tx = left + 5 + [r["month"] for r in rows].index("2026-04") * (bw + 1.5)
    parts.append(f'<line x1="{tx}" x2="{tx}" y1="{top}" y2="{top + h}" stroke="#b5462e" stroke-dasharray="3,3"/>'
                 f'<text x="{tx + 3}" y="{top + 10}">Apr 15, 2026 triage</text>')
    parts.append(f'<text x="{left}" y="{top + h + 34}">Source: NVD JSON 2.0 yearly feeds; scripts/research/coverage_by_month.py. '
                 'Current status only, not status at a fixed age.</text></svg>')
    (ROOT / "data" / "processed" / "coverage_by_month.svg").write_text("\n".join(parts))


if __name__ == "__main__":
    main(*sys.argv[1:3])
