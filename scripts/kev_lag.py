"""Median CVE-to-KEV lag by year, for the chart in section 2 ("The gate").

Lag = KEV dateAdded minus NVD published date, in calendar days, for KEV listings of CVEs
published 2022 or later (Barracuda's population, so the two can be compared).
Grouped by the year CISA added the CVE to KEV. Also writes the "legacy share": of each year's
KEV additions (any publication year), the share NVD published four or more years earlier.

    python scripts/kev_lag.py        # writes data/processed/kev_lag.json

build_site.py draws the section 2 chart and the lag sentence from this file, so rerun it
before building to refresh them. `through` is the latest KEV dateAdded in the catalog.
Reads NVD_API_KEY from .env if present.
"""
import json
import os
import pathlib
import statistics
from datetime import date

import requests

ROOT = pathlib.Path(__file__).resolve().parents[1]
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def api_key():
    env = ROOT / ".env"
    if env.exists():
        for line in env.read_text().splitlines():
            if line.startswith("NVD_API_KEY="):
                return line.split("=", 1)[1].strip()
    return os.environ.get("NVD_API_KEY", "")


def main():
    kev = requests.get(KEV_URL, timeout=120).json()
    added = {r["cveID"]: date.fromisoformat(r["dateAdded"]) for r in kev["vulnerabilities"]}

    # hasKev returns every CVE in the catalog; one page holds them all for now, but page anyway.
    published, start = {}, 0
    while True:
        page = requests.get(NVD_URL, params={"hasKev": "", "resultsPerPage": 2000, "startIndex": start},
                            headers={"apiKey": api_key()} if api_key() else {}, timeout=180).json()
        for v in page["vulnerabilities"]:
            published[v["cve"]["id"]] = date.fromisoformat(v["cve"]["published"][:10])
        start += page["resultsPerPage"]
        if start >= page["totalResults"]:
            break

    lags = {}
    for cve, d_added in added.items():
        d_pub = published.get(cve)
        if d_pub and d_pub.year >= 2022 and d_added.year >= 2023:
            lags.setdefault(d_added.year, []).append((d_added - d_pub).days)

    # Legacy share: of the CVEs CISA added in each year, how many NVD had published four or more
    # years (4 x 365.25 days) before the listing. CVE age, not code age: a CVE published in 2026 can
    # sit in code written in 2014. All publication years count here, unlike the lag above.
    legacy = {}
    for cve, d_added in added.items():
        d_pub = published.get(cve)
        if d_pub and d_added.year >= 2023:
            y = legacy.setdefault(d_added.year, {"n": 0, "published_4y_before": 0})
            y["n"] += 1
            y["published_4y_before"] += (d_added - d_pub).days >= 4 * 365.25
    for y in legacy.values():
        y["pct"] = round(100 * y["published_4y_before"] / y["n"], 1)

    out = {
        "kev_catalog_version": kev.get("catalogVersion"),
        "kev_total": len(added),
        "missing_from_nvd": len(set(added) - set(published)),
        "rule": "KEV dateAdded minus NVD published (calendar days); CVEs published 2022+; by year added",
        "through": max(added.values()).isoformat(),
        "by_year": {str(y): {"median_days": statistics.median(v), "n": len(v)} for y, v in sorted(lags.items())},
        "legacy_rule": "KEV additions per year (any publication year) whose NVD publication came 4+ years (1,461 days) before dateAdded",
        "legacy_by_year": {str(y): legacy[y] for y in sorted(legacy)},
    }
    path = ROOT / "data" / "processed" / "kev_lag.json"
    path.write_text(json.dumps(out, indent=2))
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
