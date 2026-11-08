"""When did KEV-listed CVEs first get CPE, relative to their KEV listing?

Two cohorts, both from the NVD CVE Change History API:
  - sample: KEV CVEs *published* in our 30-day window (the page's headline
    and metric 3; must match summary.json's in_kev count).
  - listed: every CVE CISA *added to KEV* in the same window, whatever its
    publication date. This catches older CVEs (some parked as Not Scheduled)
    that only reach KEV later.

For each CVE we find the first history event that added a CPE configuration
and the history event that recorded the KEV listing, and compare the two by
timestamp. That separates two questions the page used to blur:
  - Pre-KEV readiness (the "when defenders need it" test): did CPE exist
    before the KEV listing, for CVEs that were public before they were listed?
  - Post-KEV goal (metric 3): was CPE added within one business day of the
    later of KEV listing and NVD publication?

Reads:  data/processed/cves_sample.csv, data/processed/summary.json, CISA KEV feed
Writes: data/processed/kev_enrichment.json
        data/history/kev_cumulative.json: every row from every run, keyed by CVE ID (latest row wins),
        with readiness on the union. Each weekly window is rebuilt from scratch, so the window's n never
        grows; the union does. It lives in data/history/ because the weekly workflow commits that
        folder (and not other new files in data/processed/). Seeded from data/history/*/ on first run.
Run:    python scripts/kev_enrichment.py
"""
import json
import os
import sys
from datetime import date, datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).parent))
from fetch_sample import NVD_URL, fetch_kev, get_with_retry, load_dotenv  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
HISTORY_URL = "https://services.nvd.nist.gov/rest/json/cvehistory/2.0"
TRIAGE_START = "2026-04-15"   # NIST's priority triage took effect


def is_cpe_event(e):
    """A change that added CPE. Legacy case: CVEs NIST analysed before the change history logged details
    (e.g. CVE-2010-3765) have an 'Initial Analysis' event with no details, and their original CPE never
    appears as a 'CPE Configuration' detail. Without this rule their first CPE is dated to a later
    re-analysis (8 such CVEs among 2025-26 KEV adds; docs/red-team-nov7-response.md, 4b)."""
    if e.get("eventName") == "Initial Analysis" and not e.get("details"):
        return True
    return any(d.get("type") == "CPE Configuration" and d.get("action") in ("Added", "Changed")
               for d in e.get("details", []))


def history(cve_id, headers):
    """(first CPE event time, its source, KEV-listing event time, event count)."""
    r = get_with_retry(HISTORY_URL, params={"cveId": cve_id}, headers=headers)
    events = [c["change"] for c in r.json().get("cveChanges", [])]
    cpe = sorted((e["created"], e.get("sourceIdentifier")) for e in events if is_cpe_event(e))
    kev = sorted(e["created"] for e in events if "KEV" in e.get("eventName", ""))
    return (cpe[0] if cpe else (None, None)) + (kev[0] if kev else None, len(events))


def nvd_record(cve_id, headers):
    r = get_with_retry(NVD_URL, params={"cveId": cve_id}, headers=headers)
    v = r.json().get("vulnerabilities", [])
    if not v:
        return None, None
    c = v[0]["cve"]
    return c["published"][:10], c.get("vulnStatus")


def business_days_after(start, end):
    """Weekdays from start to end (no holiday calendar); 0 if end is on or before start."""
    return 0 if end <= start else int(np.busday_count(start, end))


def row_for(cve_id, kev_day, headers, in_sample):
    pub_day, status = nvd_record(cve_id, headers)
    cpe_time, cpe_source, kev_time, n = history(cve_id, headers)
    row = {"cve_id": cve_id, "in_sample": in_sample, "published": pub_day, "nvd_status": status,
           "kev_date_added": kev_day, "kev_event": kev_time, "first_cpe": cpe_time[:10] if cpe_time else None,
           "first_cpe_time": cpe_time, "first_cpe_source": cpe_source, "history_events": n}
    # Public before listing = there was time for CPE to arrive ahead of KEV.
    row["public_before_kev"] = bool(pub_day and pub_day < kev_day)
    if cpe_time:
        # Compare by timestamp when NVD logged the KEV listing; fall back to the KEV date.
        row["cpe_before_kev"] = cpe_time < kev_time if kev_time else cpe_time[:10] < kev_day
        row["cpe_before_triage"] = cpe_time[:10] < TRIAGE_START
        clock = max(kev_day, pub_day or kev_day)   # NIST can't enrich before NVD publishes
        row["business_days_kev_to_cpe"] = business_days_after(clock, row["first_cpe"])
    print({k: row[k] for k in ("cve_id", "published", "kev_date_added", "first_cpe", "nvd_status")})
    return row


def hours_after_kev(r):
    if not (r["first_cpe_time"] and r["kev_event"]):
        return None
    t = lambda s: datetime.fromisoformat(s[:19])
    return (t(r["first_cpe_time"]) - t(r["kev_event"])).total_seconds() / 3600


def stats(rows):
    done = [r for r in rows if r["first_cpe"]]
    window = [r for r in rows if r["public_before_kev"]]
    # Pre-KEV readiness under the triage: public before listing, not enriched before Apr 15, 2026.
    post = [r for r in window if not r.get("cpe_before_triage")]
    after = [r for r in post if r["first_cpe"] and not r["cpe_before_kev"]]
    return {
        "triage_public_before_kev": len(post),
        "triage_cpe_before_kev": sum(bool(r.get("cpe_before_kev")) for r in post),
        "triage_cpe_only_after_kev": len(after),
        "triage_cpe_within_2h_of_kev": sum(0 <= hours_after_kev(r) <= 2 for r in after),
        "max_days_public_without_cpe_until_kev": max(
            ((date.fromisoformat(r["kev_date_added"]) - date.fromisoformat(r["published"])).days for r in after),
            default=None),
        "kev_cves": len(rows),
        "with_cpe_now": len(done),
        "within_one_business_day": sum(r["business_days_kev_to_cpe"] <= 1 for r in done),
        "first_cpe_by_nist": sum(r["first_cpe_source"] == "nvd@nist.gov" for r in done),
        "public_before_kev": len(window),
        "cpe_before_kev_given_public": sum(bool(r.get("cpe_before_kev")) for r in window),
        "cpe_before_triage": sum(bool(r.get("cpe_before_triage")) for r in done),
        "still_without_cpe": [r["cve_id"] for r in rows if not r["first_cpe"]],
        "status_counts": dict(pd.Series([r["nvd_status"] for r in rows]).value_counts()),
    }


def update_cumulative(rows, pulled_at):
    """Append this run's rows to the cumulative file (latest row per CVE wins); return its union stats."""
    hist = ROOT / "data" / "history"
    path = hist / "kev_cumulative.json"
    if path.exists():
        cum = json.loads(path.read_text())["rows"]
    else:   # first run: seed from earlier pulls, oldest first, so later rows overwrite earlier ones
        cum = {}
        for f in sorted(hist.glob("*/kev_enrichment.json")):
            for r in json.loads(f.read_text())["rows"]:
                cum[r["cve_id"]] = {**r, "pull": f.parent.name}
    for r in rows:
        cum[r["cve_id"]] = {**r, "pull": pulled_at[:10]}
    out = {
        "about": ("Union of every KEV row from every kev_enrichment.py run (sample and listed cohorts), keyed by "
                  "CVE ID, latest row wins. Readiness rules as in kev_enrichment.json."),
        "updated_utc": pulled_at,
        "pulls": sorted({r["pull"] for r in cum.values()}),
        "union": stats(list(cum.values())),
        "rows": cum,
    }
    hist.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(out, indent=1, default=int))
    return out["union"]


def main():
    load_dotenv()
    key = os.environ.get("NVD_API_KEY")
    headers = {"apiKey": key} if key else {}

    summary = json.loads((ROOT / "data" / "processed" / "summary.json").read_text())
    start, end = (w[:10] for w in summary["window_utc"])
    df = pd.read_csv(ROOT / "data" / "processed" / "cves_sample.csv")
    sample = df[df.in_kev]
    kev = fetch_kev()
    listed_ids = sorted(c for c, d in kev.items() if d and start <= d <= end)

    rows = {}
    for _, r in sample.iterrows():
        rows[r.cve_id] = row_for(r.cve_id, r.kev_date_added, headers, in_sample=True)
    for c in listed_ids:
        if c not in rows:
            rows[c] = row_for(c, kev[c], headers, in_sample=False)

    sample_rows = [r for r in rows.values() if r["in_sample"]]
    listed_rows = [r for r in rows.values() if start <= r["kev_date_added"] <= end]
    s = stats(sample_rows)
    out = {
        "rule": ("First NVD change-history event adding a 'CPE Configuration' vs the history event recording the "
                 "KEV listing (timestamps, UTC; falls back to KEV dateAdded). Metric 3 clock starts at the later of "
                 "KEV dateAdded and NVD publication; weekdays only, no holiday calendar. first_cpe_source is the "
                 "change's sourceIdentifier (nvd@nist.gov = NIST)."),
        "window": [start, end],
        # Sample cohort at top level: the page's headline and metric 3 read these.
        **s,
        "listed_in_window": stats(listed_rows),
        "rows": list(rows.values()),
        "pulled_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    path = ROOT / "data" / "processed" / "kev_enrichment.json"
    path.write_text(json.dumps(out, indent=2, default=int))
    print(json.dumps({k: v for k, v in out.items() if k != "rows"}, indent=1, default=int))
    u = update_cumulative(list(rows.values()), out["pulled_at_utc"])
    print(f"cumulative: readiness {u['triage_cpe_before_kev']} of {u['triage_public_before_kev']} "
          f"over {u['kev_cves']} KEV CVEs seen in any pull")


if __name__ == "__main__":
    main()
