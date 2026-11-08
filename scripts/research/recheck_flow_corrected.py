"""recheck_flow_corrected.py — monthly re-queue flow at EPSS 0.05, with the change-history correction.

Question: how many CVEs a month would the re-check rule re-queue at EPSS >= 0.05, counted the same way as
the published 0.10 figures (data/processed/recheck_measured.json)? Re-queues in a window =
  stock crossers: CVEs whose EPSS first reached t in the window (first file >= t from Jun 15, 2026, the EPSS
                  v5 start; CVEs already >= t on Jun 15 are the one-time load) and that are still in the
                  stock (Deferred / Awaiting Analysis / Received, no CPE, not in KEV), plus
  enriched later: crossers published on or after 2024-02-01 that now have CPE or are in KEV, whose first
                  CPE event in the NVD change history is on or after the crossing date (or absent). Same
                  rule as kev_enrichment.is_cpe_event. CVEs published before Feb 2024 are not checked
                  (nearly all were enriched before the backlog), as in the 0.10 measurement.
t = 0.10 is re-run as a check against recheck_measured.json (28 / 23 / 11 / 12).

Inputs:  NVD JSON 2.0 yearly feeds; EPSS daily files from 2026-06-15; CISA KEV JSON; NVD change history API
         (cached in data/raw/recheck_history_cache.json)
Output:  data/processed/recheck_flow_corrected.json
Run:     python scripts/research/recheck_flow_corrected.py NVD_DIR EPSS_DIR KEV_JSON
"""
import json
import os
import sys
import time
from datetime import date
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from recheck_volume import STOCK_STATUSES, V5_START, WINDOWS, load_nvd, read_epss  # noqa: E402
from fetch_sample import get_with_retry, load_dotenv  # noqa: E402
from kev_enrichment import HISTORY_URL, is_cpe_event  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
THRESHOLDS = (0.10, 0.05)
BACKLOG_START = date(2024, 2, 1)


def first_cpe_dates(cves, headers):
    path = ROOT / "data" / "raw" / "recheck_history_cache.json"
    cache = json.loads(path.read_text()) if path.exists() else {}
    todo = [c for c in cves if c not in cache]
    for i, c in enumerate(todo, 1):
        r = get_with_retry(HISTORY_URL, params={"cveId": c}, headers=headers)
        ev = [x["change"] for x in r.json().get("cveChanges", [])]
        cpe = sorted(e["created"][:10] for e in ev if is_cpe_event(e))
        cache[c] = cpe[0] if cpe else None
        time.sleep(0.7)
        if i % 50 == 0 or i == len(todo):
            path.write_text(json.dumps(cache))
            print(f"  history {i}/{len(todo)}", flush=True)
    return cache


def main(nvd_dir, epss_dir, kev_json):
    load_dotenv()
    key = os.environ.get("NVD_API_KEY")
    headers = {"apiKey": key} if key else {}
    nvd = load_nvd(nvd_dir)
    kev = {v["cveID"] for v in json.load(open(kev_json, encoding="utf-8"))["vulnerabilities"]}
    live = {k: v for k, v in nvd.items() if v["status"] != "Rejected"}
    stock = {k for k, v in live.items() if v["status"] in STOCK_STATUSES and not v["has_cpe"] and k not in kev}

    files = sorted((date.fromisoformat(f.name[12:22]), f) for f in Path(epss_dir).glob("epss_scores-2026-*.csv.gz"))
    files = [(d, f) for d, f in files if d >= V5_START]
    first = {t: {} for t in THRESHOLDS}
    for d, f in files:
        scores, _ = read_epss(f)
        for t in THRESHOLDS:
            ft = first[t]
            for c, s in scores.items():
                if s >= t and c not in ft:
                    ft[c] = d
    print(f"EPSS files {files[0][0]}..{files[-1][0]} ({len(files)}); stock {len(stock):,}")

    crossers = {t: {(w0, w1): [c for c, d in first[t].items() if w0 <= d <= w1 and d != V5_START and c in live]
                    for w0, w1 in WINDOWS} for t in THRESHOLDS}
    cand = sorted({c for t in THRESHOLDS for cs in crossers[t].values() for c in cs
                   if c not in stock and live[c]["pub"] >= BACKLOG_START and (live[c]["has_cpe"] or c in kev)})
    print(f"change-history candidates: {len(cand)}")
    fc = first_cpe_dates(cand, headers)

    out = {"about": __doc__.split("\n\n")[0], "epss_files": [str(files[0][0]), str(files[-1][0])], "thresholds": {}}
    for t in THRESHOLDS:
        rows = []
        for (w0, w1), cs in crossers[t].items():
            stk = [c for c in cs if c in stock]
            later = [c for c in cs if c in fc and (fc[c] is None or fc[c] >= str(first[t][c]))]
            rows.append({"from": str(w0), "to": str(w1), "all_crossers": len(cs), "stock_crossers": len(stk),
                         "enriched_after_crossing": len(later), "of_which_in_kev": sum(c in kev for c in later),
                         "requeues": len(stk) + len(later)})
        out["thresholds"][f"{t:.2f}"] = rows
        print(f"t={t:.2f}", [(r["stock_crossers"], r["enriched_after_crossing"], r["requeues"]) for r in rows])
    (ROOT / "data" / "processed" / "recheck_flow_corrected.json").write_text(json.dumps(out, indent=1))


if __name__ == "__main__":
    main(*sys.argv[1:4])
