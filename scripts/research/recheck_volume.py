"""recheck_volume.py — measure the three things the Floodline day-30 estimate leaves out.

Research script (Nov 7, 2026), not part of the site build. Answers, from primary data only:
  1. Day-90 horizon: for a cohort of CVEs published Jun 15 – Jul 14, 2026 (all scored under
     EPSS v5, which started Jun 15), the share whose EPSS first reaches a threshold by day
     0 / 7 / 30 / 90 after NVD publication, and the share above it *on* day 30 / 90
     (Floodline's point-in-time definition), for comparison.
  2. Not Scheduled stock: CVEs whose current NVD status is Deferred / Awaiting Analysis /
     Received and that have no CPE, with current EPSS at >= 0.10, 0.05, 0.01 (one-time load),
     and the monthly flow of first crossings by those CVEs, split by age at crossing.
  3. Inputs for the EPSS-on-unenriched test are not computed here (see the notes file).

Inputs (download first; nothing is fetched here):
  nvd_dir   NVD JSON 2.0 yearly feeds, nvdcve-2.0-YYYY.json.gz (https://nvd.nist.gov/feeds/json/cve/2.0/)
  epss_dir  Daily EPSS archive files epss_scores-YYYY-MM-DD.csv.gz, Jun 15 – Nov 7, 2026
            (https://github.com/empiricalsec/epss_scores, linked from https://www.first.org/epss/data)
  kev_json  CISA KEV catalog JSON

Usage: python -I scripts/research/recheck_volume.py NVD_DIR EPSS_DIR KEV_JSON

Definitions:
  has_cpe     NVD record has a non-empty `configurations` array (same as fetch_sample.py).
  stock       vulnStatus in {Deferred, Awaiting Analysis, Received}, no CPE, not in KEV.
  first cross the first daily file, from Jun 15, 2026 (EPSS v5 start), on which EPSS >= t.
              A CVE already >= t on Jun 15 is "above at baseline" (part of the one-time load),
              not a crossing. Floodline counts EPSS strictly > t; we use >= (FIRST's API
              `epss-gt` filter is also inclusive). The difference is a handful of CVEs at most.
  Status and CPE are as of the feed timestamp (Nov 7, 2026). A CVE that crossed and was then
  enriched (e.g. because it entered KEV) drops out of "no CPE now", so flow counts restricted
  to "no CPE now" are biased down; counts over all CVEs are biased up. Both are reported.
"""

import csv
import gzip
import io
import json
import sys
from collections import Counter, defaultdict
from datetime import date, datetime, timedelta
from pathlib import Path

THRESHOLDS = [0.10, 0.05, 0.01]
STOCK_STATUSES = {"Deferred", "Awaiting Analysis", "Received"}
V5_START = date(2026, 6, 15)
COHORT = (date(2026, 6, 15), date(2026, 7, 14))
# Four ~30-day windows for the monthly flow, all under EPSS v5.
WINDOWS = [(date(2026, 7, 10), date(2026, 8, 8)), (date(2026, 8, 9), date(2026, 9, 7)),
           (date(2026, 9, 8), date(2026, 10, 7)), (date(2026, 10, 8), date(2026, 11, 6))]


def load_nvd(nvd_dir):
    rows = {}
    for f in sorted(Path(nvd_dir).glob("nvdcve-2.0-*.json.gz")):
        for v in json.load(gzip.open(f))["vulnerabilities"]:
            c = v["cve"]
            rows[c["id"]] = {"status": c.get("vulnStatus"),
                             "pub": date.fromisoformat(c["published"][:10]),
                             "has_cpe": bool(c.get("configurations"))}
    return rows


def read_epss(path):
    raw = gzip.decompress(Path(path).read_bytes()).decode("utf-8")
    out, version = {}, ""
    for row in csv.reader(io.StringIO(raw)):
        if not row:
            continue
        if row[0].startswith("#"):
            version = row[0]
            continue
        if row[0] == "cve":
            continue
        out[row[0]] = float(row[1])
    return out, version


def main(nvd_dir, epss_dir, kev_json):
    nvd = load_nvd(nvd_dir)
    kev = {v["cveID"] for v in json.load(open(kev_json, encoding="utf-8"))["vulnerabilities"]}
    live = {k: v for k, v in nvd.items() if v["status"] != "Rejected"}
    print(f"NVD records: {len(nvd):,}; non-rejected: {len(live):,}; KEV entries: {len(kev):,}")
    print("Status counts (non-rejected):", dict(Counter(v["status"] for v in live.values()).most_common()))

    stock = {k for k, v in live.items() if v["status"] in STOCK_STATUSES and not v["has_cpe"] and k not in kev}
    stock_kev = {k for k, v in live.items() if v["status"] in STOCK_STATUSES and not v["has_cpe"] and k in kev}
    print(f"\nStock (Deferred/Awaiting/Received, no CPE, not KEV): {len(stock):,}  (+{len(stock_kev)} in KEV)")
    print("  by status:", dict(Counter(live[k]["status"] for k in stock)))
    print("  by publication year:", dict(sorted(Counter(live[k]["pub"].year for k in stock).items())))
    no_cpe_any = {k for k, v in live.items() if not v["has_cpe"]}
    print(f"  all non-rejected without CPE (any status): {len(no_cpe_any):,}; by status:",
          dict(Counter(live[k]["status"] for k in no_cpe_any).most_common()))

    files = sorted(Path(epss_dir).glob("epss_scores-2026-*.csv.gz"))
    files = [(date.fromisoformat(f.name[12:22]), f) for f in files]
    files = [(d, f) for d, f in files if d >= V5_START]
    print(f"\nEPSS files: {len(files)} ({files[0][0]} .. {files[-1][0]})")

    first = {t: {} for t in THRESHOLDS}      # cve -> first date >= t (from V5_START)
    cohort = {k for k, v in live.items() if COHORT[0] <= v["pub"] <= COHORT[1]}
    cohort_scores = defaultdict(dict)        # cve -> {date: score}
    versions = Counter()
    latest = {}
    for d, f in files:
        scores, ver = read_epss(f)
        versions[ver.split(",")[0]] += 1
        for t in THRESHOLDS:
            ft = first[t]
            for c, s in scores.items():
                if s >= t and c not in ft:
                    ft[c] = d
        for c in cohort:
            if c in scores:
                cohort_scores[c][d] = scores[c]
        latest = scores
    print("model versions seen:", dict(versions))
    days = {d for d, _ in files}

    # ---- 2a. one-time load: stock above threshold on the latest file ----
    print(f"\n== One-time load: stock CVEs with EPSS >= t on {files[-1][0]} ==")
    scored = [k for k in stock if k in latest]
    print(f"stock scored by EPSS: {len(scored):,} of {len(stock):,}")
    for t in THRESHOLDS:
        hit = [k for k in stock if latest.get(k, 0) >= t]
        print(f"  >= {t:.2f}: {len(hit):,}  by status {dict(Counter(live[k]['status'] for k in hit))}"
              f"  pub<2026-03-01: {sum(live[k]['pub'] < date(2026, 3, 1) for k in hit):,}")
    for t in THRESHOLDS:
        allc = sum(1 for k in live if latest.get(k, 0) >= t)
        print(f"  context: all non-rejected CVEs >= {t:.2f}: {allc:,}")

    # ---- 2b. monthly flow of first crossings, by age at crossing ----
    print("\n== Monthly flow: CVEs whose EPSS first reached t inside each window (first seen >= t after Jun 15) ==")
    def bucket(age):
        return "0-30d" if age <= 30 else "31-90d" if age <= 90 else ">90d"
    for t in THRESHOLDS:
        print(f"-- t = {t:.2f}")
        for w0, w1 in WINDOWS:
            ev = [c for c, d in first[t].items() if w0 <= d <= w1 and d != V5_START and c in live]
            allb = Counter(bucket((first[t][c] - live[c]["pub"]).days) for c in ev)
            nocpe = [c for c in ev if not live[c]["has_cpe"] and c not in kev]
            nob = Counter(bucket((first[t][c] - live[c]["pub"]).days) for c in nocpe)
            stk = [c for c in ev if c in stock]
            stb = Counter(bucket((first[t][c] - live[c]["pub"]).days) for c in stk)
            print(f"  {w0}..{w1}: all {len(ev):,} {dict(allb)} | no CPE now, not KEV {len(nocpe):,} {dict(nob)}"
                  f" | in stock statuses {len(stk):,} {dict(stb)}")

    # ---- 1. day-90 cohort ----
    print(f"\n== Day-90 cohort: non-rejected CVEs NVD-published {COHORT[0]}..{COHORT[1]} ==")
    n = len(cohort)
    print(f"cohort size: {n:,}; with CPE now: {sum(live[c]['has_cpe'] for c in cohort):,};"
          f" in KEV: {len(cohort & kev)}; status now: {dict(Counter(live[c]['status'] for c in cohort))}")
    for t in THRESHOLDS:
        line = []
        for h in (0, 7, 30, 90):
            ever = [c for c in cohort if c in first[t] and (first[t][c] - live[c]["pub"]).days <= h]
            line.append(f"by d{h}: {len(ever)} ({100 * len(ever) / n:.3f}%)")
        print(f"  t={t:.2f} ever reached ->", "; ".join(line))
        # point-in-time at exact day (Floodline style, but >=); only cohorts whose day is observed
        for h in (30, 90):
            el = [c for c in cohort if live[c]["pub"] + timedelta(days=h) in days]
            above = [c for c in el if cohort_scores[c].get(live[c]["pub"] + timedelta(days=h), 0) >= t]
            print(f"     on day {h} (point-in-time): {len(above)} of {len(el)} eligible")
        between = [c for c in cohort if c in first[t] and 30 < (first[t][c] - live[c]["pub"]).days <= 90]
        nocpe = [c for c in between if not live[c]["has_cpe"] and c not in kev]
        print(f"     first reached in day 31-90: {len(between)}; of those no CPE now & not KEV: {len(nocpe)}"
              f"; list: {sorted(between)[:20]}")
        by30 = [c for c in cohort if c in first[t] and (first[t][c] - live[c]["pub"]).days <= 30]
        print(f"     by d30 detail: no CPE now & not KEV {sum(1 for c in by30 if not live[c]['has_cpe'] and c not in kev)},"
              f" KEV {sum(1 for c in by30 if c in kev)}, has CPE {sum(1 for c in by30 if live[c]['has_cpe'])}")
    # sanity: first-score lag
    lag = [min(cohort_scores[c]) - live[c]["pub"] for c in cohort if cohort_scores[c]]
    print(f"  scored at all: {len(lag):,}; median days pub->first EPSS file: "
          f"{sorted(x.days for x in lag)[len(lag) // 2] if lag else None}")


if __name__ == "__main__":
    main(*sys.argv[1:4])
