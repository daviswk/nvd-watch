"""trigger_volume.py — volume of the SSVC and LEV re-check triggers on the current stock (M3, M4).

Question: if NIST re-queued every stock CVE (no CPE, status Deferred / Awaiting Analysis / Received,
not in KEV) when a trigger fires, how many would it re-queue once (one-time load) and per month (flow)?
EPSS thresholds are measured by recheck_volume.py; this adds:
  - SSVC: CISA Vulnrichment (CISA-ADP container in the CVE record) Exploitation = poc or active.
    One-time load = stock CVEs with that value now. Flow = those whose SSVC `timestamp` falls in each
    window. The timestamp is the latest evaluation (CISA sometimes back-dates it, see the response
    doc), so flow is an approximation; the first poc/active date may be earlier.
  - LEV (NIST CSWP 41): LEV >= 1 - prod_i (1 - epss(d_i) * w_i) over 30-day steps. We evaluate it on
    one fixed grid of EPSS files every 30 days back from 2026-11-07 (to 2021-04-14), all weights 1;
    CSWP 41 anchors its grid at the first score date instead, so this is an approximation. The grid
    mixes EPSS models v3/v4/v5. LEV is computed from EPSS, so it is not an independent signal.
    Flow = stock CVEs whose LEV goes from below t to >= t between consecutive grid dates (30 days).
  - M4 benefit: sum of current EPSS over each trigger's one-time load = expected number of CVEs with
    exploitation *activity* observed in the next 30 days (EPSS is a 30-day probability of exploitation
    activity, not of compromise).

Inputs (download first; see docs/red-team-nov7-response.md):
  nvd_dir      NVD JSON 2.0 yearly feeds nvdcve-2.0-YYYY.json.gz
  epss_dir     EPSS daily files epss_scores-YYYY-MM-DD.csv.gz (the 30-day grid back from 2026-11-07)
  cves_zip     cvelistV5 bulk cves.zip (inner zip of the daily "all_CVEs_at_midnight" release)
  kev_json     CISA KEV catalog JSON
Output: data/processed/trigger_volume.json
Run:    python -I scripts/research/trigger_volume.py NVD_DIR EPSS_DIR CVES_ZIP KEV_JSON
"""
import json
import sys
import zipfile
from datetime import date, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from recheck_volume import STOCK_STATUSES, load_nvd, read_epss  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
END = date(2026, 11, 7)
GRID = [END - timedelta(30 * k) for k in range(0, 70) if END - timedelta(30 * k) >= date(2021, 4, 14)]
WINDOWS = [(date(2026, 7, 10), date(2026, 8, 8)), (date(2026, 8, 9), date(2026, 9, 7)),
           (date(2026, 9, 8), date(2026, 10, 7)), (date(2026, 10, 8), date(2026, 11, 7))]
THRESHOLDS = [0.10, 0.05, 0.01]


def ssvc_of(rec):
    """(exploitation, timestamp) from the CISA-ADP SSVC metric, or (None, None)."""
    for adp in rec.get("containers", {}).get("adp", []):
        for m in adp.get("metrics", []):
            o = m.get("other", {})
            if o.get("type") == "ssvc":
                c = o.get("content", {})
                opts = {k.lower(): v for d in c.get("options", []) for k, v in d.items()}
                return opts.get("exploitation"), c.get("timestamp")
    return None, None


def main(nvd_dir, epss_dir, cves_zip, kev_json):
    nvd = load_nvd(nvd_dir)
    kev = {v["cveID"] for v in json.load(open(kev_json, encoding="utf-8"))["vulnerabilities"]}
    stock = {k for k, v in nvd.items() if v["status"] in STOCK_STATUSES and not v["has_cpe"] and k not in kev}
    print(f"stock: {len(stock):,}")

    # ---- SSVC from cvelistV5 ----
    ssvc = {}
    with zipfile.ZipFile(cves_zip) as z:
        for name in z.namelist():
            cve = name.rsplit("/", 1)[-1][:-5]
            if name.endswith(".json") and cve in stock:
                ssvc[cve] = ssvc_of(json.loads(z.read(name)))
    have = sum(1 for v in ssvc.values() if v[0])
    print(f"stock CVEs in cvelistV5: {len(ssvc):,}; with a CISA-ADP SSVC decision: {have:,}")
    exp_counts = {}
    for v in ssvc.values():
        exp_counts[str(v[0])] = exp_counts.get(str(v[0]), 0) + 1
    fired = {c: v for c, v in ssvc.items() if v[0] in ("poc", "active")}
    ssvc_flow = []
    for w0, w1 in WINDOWS:
        n = sum(1 for v in fired.values() if v[1] and w0 <= date.fromisoformat(v[1][:10]) <= w1)
        ssvc_flow.append({"from": str(w0), "to": str(w1), "requeues": n})

    # ---- EPSS grid for LEV ----
    files = {d: Path(epss_dir) / f"epss_scores-{d}.csv.gz" for d in GRID}
    missing = [str(d) for d, f in files.items() if not f.exists()]
    if missing:
        sys.exit(f"missing EPSS grid files: {missing}")
    hist = {c: {} for c in stock}
    versions = {}
    latest = {}
    for d in sorted(GRID):
        scores, ver = read_epss(files[d])
        versions[str(d)] = ver.split(",")[0].replace("#model_version:", "")
        for c in stock:
            if c in scores:
                hist[c][d] = scores[c]
        if d == END:
            latest = scores

    def lev_at(c, g):
        p = 1.0
        for d, s in hist[c].items():
            if d <= g:
                p *= 1 - s
        return 1 - p

    LEV_GRID = sorted(GRID)[-5:]                      # Jul 10, Aug 9, Sep 8, Oct 8, Nov 7
    lev_g = {g: {c: lev_at(c, g) for c in stock} for g in LEV_GRID}
    lev_now = lev_g[END]
    out = {"_about": __doc__.split("\n\n")[0], "stock": len(stock), "measured_on": str(END),
           "epss_grid_models": sorted(set(versions.values())),
           "ssvc": {"stock_in_cvelist": len(ssvc), "with_ssvc_decision": have, "exploitation_counts": exp_counts,
                    "one_time_load": len(fired),
                    "one_time_by_value": {v: sum(1 for x in fired.values() if x[0] == v) for v in ("poc", "active")},
                    "expected_events_30d": round(sum(latest.get(c, 0) for c in fired), 2),
                    "monthly_flow": ssvc_flow,
                    "flow_note": "by SSVC timestamp (latest evaluation); approximate"},
           "epss": {}, "lev": {}}
    for t in THRESHOLDS:
        e = [c for c in stock if latest.get(c, 0) >= t]
        out["epss"][f"{t:.2f}"] = {"one_time_load": len(e),
                                   "expected_events_30d": round(sum(latest[c] for c in e), 2)}
        lv = [c for c in stock if lev_now[c] >= t]
        flow = []
        for g0, g1 in zip(LEV_GRID, LEV_GRID[1:]):   # LEV only changes on grid dates
            n = sum(1 for c in stock if lev_g[g0][c] < t <= lev_g[g1][c])
            flow.append({"after": str(g0), "through": str(g1), "requeues": n})
        out["lev"][f"{t:.2f}"] = {"one_time_load": len(lv),
                                  "not_already_epss_ge_t": sum(1 for c in lv if latest.get(c, 0) < t),
                                  "expected_events_30d": round(sum(latest.get(c, 0) for c in lv), 2),
                                  "monthly_flow": flow}
    # union of the rule's triggers at 0.10: EPSS or LEV or SSVC
    u = {c for c in stock if latest.get(c, 0) >= 0.10 or lev_now[c] >= 0.10} | set(fired)
    out["union_0_10"] = {"one_time_load": len(u), "expected_events_30d": round(sum(latest.get(c, 0) for c in u), 2)}
    path = ROOT / "data" / "processed" / "trigger_volume.json"
    path.write_text(json.dumps(out, indent=1))
    print(json.dumps({k: v for k, v in out.items() if k != "_about"}, indent=1))


if __name__ == "__main__":
    main(*sys.argv[1:5])
