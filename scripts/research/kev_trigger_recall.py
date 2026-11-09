"""kev_trigger_recall.py — would each re-check trigger have fired before the KEV listing? (M3, M1, S3)

Question: of the CVEs CISA added to KEV Jan 1, 2025 – Nov 7, 2026 that were public before listing but
had no CPE before NVD recorded the listing, how many would each trigger have caught in time?
  EPSS >= 0.10 / 0.05 / 0.01  on the EPSS score dated the day before the KEV listing (FIRST API `date=`)
  SSVC Exploitation poc|active  CISA-ADP SSVC values as logged in the NVD change history (dated by the
                                change-history event; also reported as >= 24 h before listing)
  LEV >= 0.10                   NIST CSWP 41 lower bound from EPSS every 30 days back from the day
                                before listing (to publication or 2021-04-14), weights 1. Not an
                                independent signal: it is a function of EPSS history.
Rows are tagged with the EPSS model in force on the day before listing (v3 before 2025-03-17,
v4 to 2026-06-14, v5 from 2026-06-15; FIRST data page / archive headers).

It also writes the M1 (readiness by period) and S3 (1 vs 7 days public) tables, because they use the
same rows. Readiness rows come from kev_history_rows.py (kev_enrichment.py's rules). One correction:
CVEs NIST analysed before its change history logged details have an "Initial Analysis" event with no
details; their original CPE never appears as a "CPE Configuration" event, so the rule the cached rows
were built with dated their first CPE to a later re-analysis. Such CVEs are counted here as having CPE
before listing ("legacy analysis") and reported separately. kev_enrichment.py has had the same rule
since Nov 8, 2026 (`is_cpe_event`), so rows fetched after that date no longer need the correction.

Inputs:  data/raw/kev_history_rows.json (run kev_history_rows.py first); NVD change history API; FIRST
         EPSS API. Caches: data/raw/kev_history_events.json, data/raw/epss_api_cache.json
Output:  data/processed/kev_trigger_recall.json
Run:     python scripts/research/kev_trigger_recall.py
"""
import json
import os
import sys
import time
from datetime import date, timedelta
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from fetch_sample import EPSS_URL, get_with_retry, load_dotenv  # noqa: E402
from kev_enrichment import HISTORY_URL  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
RAW = ROOT / "data" / "raw"
EPSS_START = date(2021, 4, 14)
PERIODS = {"Oct 8 – Nov 7, 2025 (pre-triage)": ("2025-10-08", "2025-11-07"),
           "Jan 8 – Feb 7, 2026 (pre-triage)": ("2026-01-08", "2026-02-07"),
           "Oct 8 – Nov 7, 2026 (under triage)": ("2026-10-08", "2026-11-07")}


def model(d):
    return "v3" if d < "2025-03-17" else "v4" if d < "2026-06-15" else "v5"


def events_for(cves, headers):
    path = RAW / "kev_history_events.json"
    cache = json.loads(path.read_text()) if path.exists() else {}
    for c in [c for c in cves if c not in cache]:
        r = get_with_retry(HISTORY_URL, params={"cveId": c}, headers=headers)
        ev = []
        for x in r.json().get("cveChanges", []):
            e = x["change"]
            ssvc = [d["newValue"] for d in e.get("details", [])
                    if d.get("type") == "SSVC" and d.get("action") == "Added" and isinstance(d.get("newValue"), dict)]
            ev.append({"created": e["created"], "name": e["eventName"], "n_details": len(e.get("details", [])),
                       "ssvc_exploitation": [{k.lower(): v for o in s.get("options", []) for k, v in o.items()}
                                             .get("exploitation") for s in ssvc]})
        cache[c] = ev
        time.sleep(0.7)
        path.write_text(json.dumps(cache))
    return cache


def epss_on(pairs):
    """{(cve, date): score or None} via FIRST API, batched by date, cached."""
    path = RAW / "epss_api_cache.json"
    cache = json.loads(path.read_text()) if path.exists() else {}
    by_date = {}
    for c, d in pairs:
        if f"{c}|{d}" not in cache:
            by_date.setdefault(d, []).append(c)
    for d, cs in sorted(by_date.items()):
        for i in range(0, len(cs), 100):
            chunk = cs[i:i + 100]
            try:
                r = get_with_retry(EPSS_URL, params={"cve": ",".join(chunk), "date": d})
                got = {x["cve"]: float(x["epss"]) for x in r.json().get("data", [])}
            except requests.HTTPError as e:   # FIRST answers 422 "listNoResults" when no CVE has a score
                if e.response is None or e.response.status_code != 422:
                    raise
                got = {}
            for c in chunk:
                cache[f"{c}|{d}"] = got.get(c)
            time.sleep(0.3)
        path.write_text(json.dumps(cache))
    return {tuple(k.split("|")): v for k, v in cache.items()}


def readiness(rows, legacy):
    pub = [r for r in rows if r["public_before_kev"]]
    ready = [r for r in pub if r.get("cpe_before_kev") or r["cve_id"] in legacy]
    young = [r for r in pub if (date.fromisoformat(r["kev_date_added"]) - date.fromisoformat(r["published"])).days <= 90]
    return {"kev_cves": len(rows), "excluded_not_public_before_listing": len(rows) - len(pub),
            "public_before_listing": len(pub), "cpe_before_listing": len(ready),
            "of_which_legacy_analysis": sum(r["cve_id"] in legacy for r in ready),
            "young_public_le_90d": len(young),
            "young_cpe_before_listing": sum(1 for r in young if r.get("cpe_before_kev") or r["cve_id"] in legacy),
            "excluded_cpe_before_triage_page_rule": sum(1 for r in pub if r.get("cpe_before_triage")
                                                        and r["kev_date_added"] >= "2026-04-15"),
            "page_rule_n": sum(1 for r in pub if not (r.get("cpe_before_triage") and r["kev_date_added"] >= "2026-04-15")),
            "page_rule_ready": sum(1 for r in pub if (r.get("cpe_before_kev") or r["cve_id"] in legacy)
                                   and not (r.get("cpe_before_triage") and r["kev_date_added"] >= "2026-04-15"))}


def main():
    load_dotenv()
    key = os.environ.get("NVD_API_KEY")
    headers = {"apiKey": key} if key else {}
    rows = list(json.loads((RAW / "kev_history_rows.json").read_text()).values())
    rows = [r for r in rows if "2025-01-01" <= r["kev_date_added"] <= "2026-11-07"]
    nocpe = [r for r in rows if r["public_before_kev"] and not r.get("cpe_before_kev")]
    ev = events_for([r["cve_id"] for r in nocpe], headers)
    legacy = {r["cve_id"] for r in nocpe
              if any(e["name"] == "Initial Analysis" and e["n_details"] == 0 and e["created"] < r["kev_event"]
                     for e in ev[r["cve_id"]])}
    cohort = [r for r in nocpe if r["cve_id"] not in legacy]
    print(f"KEV adds: {len(rows)}; public before listing without CPE before listing: {len(nocpe)}; "
          f"legacy analysis (had CPE, history silent): {len(legacy)}; recall cohort: {len(cohort)}")

    # EPSS day before listing, and the 30-day LEV grid
    need = set()
    grid = {}
    for r in cohort:
        dn = date.fromisoformat(r["kev_date_added"]) - timedelta(1)
        start = max(date.fromisoformat(r["published"]), EPSS_START)
        g = [dn - timedelta(30 * k) for k in range(0, 400) if dn - timedelta(30 * k) >= start]
        grid[r["cve_id"]] = [str(d) for d in g]
        need |= {(r["cve_id"], str(d)) for d in g}
    scores = epss_on(sorted(need))

    out_rows = []
    for r in cohort:
        c, g = r["cve_id"], grid[r["cve_id"]]
        e1 = scores.get((c, g[0])) if g else None
        vals = [scores.get((c, d)) for d in g]
        lev = 1.0
        for v in vals:
            lev *= 1 - (v or 0)
        ssvc_before = [(e["created"], x) for e in ev[c] for x in e["ssvc_exploitation"]
                       if x in ("poc", "active") and e["created"] < r["kev_event"]]
        first_ssvc = min(ssvc_before)[0] if ssvc_before else None
        lead_h = None
        if first_ssvc:
            t = lambda s: time.mktime(time.strptime(s[:19], "%Y-%m-%dT%H:%M:%S"))
            lead_h = round((t(r["kev_event"]) - t(first_ssvc)) / 3600, 1)
        out_rows.append({
            "cve_id": c, "published": r["published"], "kev_date_added": r["kev_date_added"],
            "days_public": (date.fromisoformat(r["kev_date_added"]) - date.fromisoformat(r["published"])).days,
            "epss_model": model(g[0]) if g else model(r["kev_date_added"]),
            "epss_day_before": e1, "lev_day_before": round(1 - lev, 4) if g else None,
            "ssvc_poc_or_active_before_listing": bool(ssvc_before),
            "ssvc_first_value": min(ssvc_before)[1] if ssvc_before else None,
            "ssvc_lead_hours": lead_h, "ssvc_any_evaluation_before": any(
                e["ssvc_exploitation"] and e["created"] < r["kev_event"] for e in ev[c]),
        })

    def recall(sel, name):
        res = {"n": len(sel), "epss_scored_day_before": sum(x["epss_day_before"] is not None for x in sel)}
        for t in (0.10, 0.05, 0.01):
            res[f"epss_ge_{t:.2f}"] = sum((x["epss_day_before"] or 0) >= t for x in sel)
        res["lev_ge_0.10"] = sum((x["lev_day_before"] or 0) >= 0.10 for x in sel)
        res["ssvc_poc_or_active_any_time_before"] = sum(x["ssvc_poc_or_active_before_listing"] for x in sel)
        res["ssvc_poc_or_active_24h_before"] = sum((x["ssvc_lead_hours"] or 0) >= 24 for x in sel)
        res["ssvc_poc_24h_before"] = sum((x["ssvc_lead_hours"] or 0) >= 24 and x["ssvc_first_value"] == "poc" for x in sel)
        res["ssvc_evaluated_before_listing"] = sum(x["ssvc_any_evaluation_before"] for x in sel)
        res["any_of_epss10_lev10_ssvc24h"] = sum((x["epss_day_before"] or 0) >= 0.10 or (x["lev_day_before"] or 0) >= 0.10
                                                 or (x["ssvc_lead_hours"] or 0) >= 24 for x in sel)
        print(name, res)
        return res

    recall_tbl = {"all": recall(out_rows, "all")}
    for m in ("v3", "v4", "v5"):
        recall_tbl[f"epss_{m}"] = recall([x for x in out_rows if x["epss_model"] == m], m)
    recall_tbl["public_ge_7d"] = recall([x for x in out_rows if x["days_public"] >= 7], ">=7d")

    m1 = {}
    for name, (a, b) in PERIODS.items():
        m1[name] = readiness([r for r in rows if a <= r["kev_date_added"] <= b], legacy)
        print(name, m1[name])

    cur = [r for r in rows if "2026-10-08" <= r["kev_date_added"] <= "2026-11-07" and r["public_before_kev"]
           and not r.get("cpe_before_triage")]
    dp = lambda r: (date.fromisoformat(r["kev_date_added"]) - date.fromisoformat(r["published"])).days
    s3 = {}
    for cut in (1, 7):
        sel = [r for r in cur if dp(r) >= cut]
        s3[f"public_ge_{cut}d"] = {"ready": sum(bool(r.get("cpe_before_kev")) for r in sel), "n": len(sel)}
    lack = sorted(dp(r) for r in cur if not r.get("cpe_before_kev"))
    s3["days_public_without_cpe"] = {"values": lack, "median": lack[len(lack) // 2] if lack else None,
                                     "max": max(lack, default=None)}

    out = {"about": __doc__.split("\n\n")[0], "kev_range": ["2025-01-01", "2026-11-07"],
           "legacy_analysis_cves": sorted(legacy), "recall": recall_tbl, "m1_readiness_by_period": m1,
           "s3_current_listed_cohort": s3, "rows": out_rows}
    (ROOT / "data" / "processed" / "kev_trigger_recall.json").write_text(json.dumps(out, indent=1))
    print("S3", s3)


if __name__ == "__main__":
    main()
