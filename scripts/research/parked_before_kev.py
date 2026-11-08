"""parked_before_kev.py — what NVD status did each KEV CVE without prior CPE have before listing? (M2)

Question: the 13 CVEs in the current listed cohort that were public before their KEV listing but got
CPE only after it. Were they parked (Not Scheduled = API `Deferred`) or merely queued (Received /
Awaiting Analysis / Undergoing Analysis) when CISA listed them? "Parked" supports a side-door story
(a request channel would have mattered); "queued" is a queue-speed story.

Source: the fkie-cad/nvd-json-data-feeds mirror (https://github.com/fkie-cad/nvd-json-data-feeds),
which commits a copy of every changed NVD CVE record roughly every 1-2 hours. For each CVE we list the
commits that touched its file (GitHub API, unauthenticated: one call per CVE), fetch every version
committed up to the KEV listing (raw.githubusercontent.com), and read `vulnStatus` and whether
`configurations` (CPE) is present. Mirror commit time = when the mirror saw the change; NVD's own
timestamp (`lastModified`) is kept too. The mirror lags NVD by up to ~2 h, so the status "the day
before listing" is taken from the last version committed before 00:00 UTC of the KEV date.

Inputs:  data/processed/kev_enrichment.json (listed cohort; pull of 2026-11-08)
Outputs: data/processed/parked_before_kev.json
Re-run:  python scripts/research/parked_before_kev.py   (13 GitHub API calls + ~50 raw fetches; NVD history
         fallback for CVEs the mirror has no earlier version of)
"""
import json
import os
import sys
import time
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parents[2]
API = "https://api.github.com/repos/fkie-cad/nvd-json-data-feeds/commits"
RAW = "https://raw.githubusercontent.com/fkie-cad/nvd-json-data-feeds/{sha}/{path}"
UA = {"User-Agent": "nvd-watch-research"}
DISPLAY = {"Deferred": "Not Scheduled", "Awaiting Analysis": "Awaiting Enrichment",
           "Received": "Received", "Undergoing Analysis": "Undergoing Enrichment", "Analyzed": "Enriched",
           "Modified": "Modified"}


def mirror_path(cve):
    _, year, num = cve.split("-")
    return f"CVE-{year}/CVE-{year}-{num[:-2]}xx/{cve}.json"


def nvd_events_before(cve, kev_event):
    """Fallback when the mirror has no earlier version: NVD change-history event names before listing."""
    sys.path.insert(0, str(ROOT / "scripts"))
    from fetch_sample import get_with_retry, load_dotenv
    load_dotenv()
    r = get_with_retry("https://services.nvd.nist.gov/rest/json/cvehistory/2.0", params={"cveId": cve},
                       headers={"apiKey": os.environ.get("NVD_API_KEY", "")})
    names = [c["change"]["eventName"] for c in r.json()["cveChanges"] if c["change"]["created"] < kev_event]
    return "NVD change history before listing: " + ", ".join(names) + " (no analysis event, so not enriched)"


def cohort():
    k = json.loads((ROOT / "data" / "processed" / "kev_enrichment.json").read_text())
    s, e = k["window"]
    return k["window"], [r for r in k["rows"] if s <= r["kev_date_added"] <= e and r["public_before_kev"]
                         and not r.get("cpe_before_triage") and not r.get("cpe_before_kev")]


def main():
    window, rows = cohort()
    out = []
    for r in rows:
        cve, path = r["cve_id"], mirror_path(r["cve_id"])
        commits = requests.get(API, params={"path": path, "per_page": 100}, headers=UA, timeout=60).json()
        versions = []
        for c in sorted(commits, key=lambda c: c["commit"]["committer"]["date"]):
            t = c["commit"]["committer"]["date"].rstrip("Z")
            if t > r["kev_event"][:19]:
                break
            rec = requests.get(RAW.format(sha=c["sha"], path=path), headers=UA, timeout=60).json()
            versions.append({"mirror_commit_utc": t, "sha": c["sha"][:12], "vulnStatus": rec.get("vulnStatus"),
                             "has_cpe": bool(rec.get("configurations")), "lastModified": rec.get("lastModified")})
            time.sleep(0.2)
        day_before = [v for v in versions if v["mirror_commit_utc"] < r["kev_date_added"]]
        last = (day_before or versions or [None])[-1]
        out.append({"cve_id": cve, "published": r["published"], "kev_date_added": r["kev_date_added"],
                     "kev_event": r["kev_event"], "first_cpe_time": r["first_cpe_time"],
                     "status_day_before_listing": last and last["vulnStatus"],
                     "status_display": last and DISPLAY.get(last["vulnStatus"], last["vulnStatus"]),
                     "status_sequence_before_listing": [v["vulnStatus"] for v in versions],
                     "source": f"fkie-cad mirror commit {last['sha']} ({last['mirror_commit_utc']}Z)" if last
                     else "unknown: no mirror version before listing; " + nvd_events_before(cve, r["kev_event"]),
                     "versions": versions})
        print(cve, r["kev_date_added"], out[-1]["status_sequence_before_listing"], "->", out[-1]["status_display"])
    result = {"question": "NVD status of each listed-cohort KEV CVE without CPE before listing, the day before listing",
              "cohort_window": window, "n": len(out),
              "counts": {s: sum(str(o["status_display"]) == s for o in out) for s in sorted({str(o["status_display"]) for o in out})},
              "rows": out}
    (ROOT / "data" / "processed" / "parked_before_kev.json").write_text(json.dumps(result, indent=1))
    print(result["counts"])


if __name__ == "__main__":
    main()
