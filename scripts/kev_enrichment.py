"""When did KEV-listed CVEs first get CPE, relative to their KEV listing?

For every CVE in our 30-day sample that CISA has added to KEV, ask the NVD
CVE Change History API for its history and find the first change event that
added a CPE configuration. Compare that date with KEV `dateAdded`.

Answers two questions on the page:
  - Harm metric: did the CVE lack CPE on the day exploitation was confirmed
    (KEV listing date)? How long did it stay that way?
  - Metric 3: did NIST meet its goal of enriching KEV CVEs within one
    business day of listing?

Reads:  data/processed/cves_sample.csv (from fetch_sample.py)
Writes: data/processed/kev_enrichment.json

Run:    python scripts/kev_enrichment.py
"""
import json
import os
import sys
from datetime import date, datetime, timedelta
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).parent))
from fetch_sample import get_with_retry, load_dotenv  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
HISTORY_URL = "https://services.nvd.nist.gov/rest/json/cvehistory/2.0"


def first_cpe_date(cve_id, headers):
    """Date of the first history event that added a CPE configuration, or None."""
    r = get_with_retry(HISTORY_URL, params={"cveId": cve_id}, headers=headers)
    events = [c["change"] for c in r.json().get("cveChanges", [])]
    hits = []
    for ev in events:
        for d in ev.get("details", []):
            if d.get("type") == "CPE Configuration" and d.get("action") in ("Added", "Changed"):
                hits.append((ev["created"], ev.get("sourceIdentifier")))
                break
    if not hits:
        return None, None, len(events)
    created, source = min(hits)
    return created[:10], source, len(events)


def business_days_after(start, end):
    """Business days (Mon-Fri, no holiday calendar) from start to end; 0 if same day or earlier."""
    if end <= start:
        return 0
    return int(np.busday_count(start, end))


def main():
    load_dotenv()
    key = os.environ.get("NVD_API_KEY")
    headers = {"apiKey": key} if key else {}

    df = pd.read_csv(ROOT / "data" / "processed" / "cves_sample.csv")
    kev = df[df.in_kev].copy()
    rows = []
    for _, r in kev.iterrows():
        cpe_day, cpe_source, n_events = first_cpe_date(r.cve_id, headers)
        kev_day = r.kev_date_added
        pub_day = r.published[:10]
        row = {
            "cve_id": r.cve_id,
            "published": pub_day,
            "kev_date_added": kev_day,
            "first_cpe": cpe_day,
            "first_cpe_source": cpe_source,
            "history_events": n_events,
        }
        if cpe_day:
            row["cpe_before_or_on_kev_day"] = cpe_day <= kev_day
            row["days_kev_to_cpe"] = max(0, (date.fromisoformat(cpe_day) - date.fromisoformat(kev_day)).days)
            # NIST cannot enrich before NVD publishes the CVE, so its clock starts
            # at the later of KEV listing and NVD publication.
            clock = max(kev_day, pub_day)
            row["business_days_kev_to_cpe"] = business_days_after(clock, cpe_day)
            row["days_pub_to_cpe"] = (date.fromisoformat(cpe_day) - date.fromisoformat(pub_day)).days
        rows.append(row)
        print(row)

    done = [x for x in rows if x["first_cpe"]]
    out = {
        "rule": ("First NVD change-history event adding a 'CPE Configuration', compared with KEV dateAdded. "
                 "Dates in UTC. The one-business-day clock starts at the later of KEV listing and NVD publication. Business days are Mon-Fri with no federal-holiday calendar. "
                 "first_cpe_source is the change's sourceIdentifier (nvd@nist.gov = NIST)."),
        "kev_cves": len(rows),
        "with_cpe_now": len(done),
        "cpe_by_kev_day": sum(x["cpe_before_or_on_kev_day"] for x in done),
        "cpe_after_kev_day": sum(not x["cpe_before_or_on_kev_day"] for x in done),
        "within_one_business_day": sum(x["business_days_kev_to_cpe"] <= 1 for x in done),
        "first_cpe_by_nist": sum(x["first_cpe_source"] == "nvd@nist.gov" for x in done),
        "enriched_before_kev": sum(x["first_cpe"] < x["kev_date_added"] for x in done),
        "max_days_kev_to_cpe": max((x["days_kev_to_cpe"] for x in done), default=None),
        "still_without_cpe": [x["cve_id"] for x in rows if not x["first_cpe"]],
        "rows": rows,
        "pulled_at_utc": datetime.utcnow().isoformat(timespec="seconds") + "Z",
    }
    path = ROOT / "data" / "processed" / "kev_enrichment.json"
    path.write_text(json.dumps(out, indent=2))
    print({k: v for k, v in out.items() if k != "rows"})


if __name__ == "__main__":
    main()
