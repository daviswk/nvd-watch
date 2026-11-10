"""
fetch_sample.py — the data pull for NVD Watch (first step of the weekly rebuild).

What it does, in order:
  1. Downloads every CVE published in the last N days from the NVD API 2.0.
  2. Downloads the CISA KEV catalog.
  3. Looks up current EPSS scores from FIRST for those CVEs.
  4. Writes one row per CVE with simple yes/no flags, plus a summary.

Why these flags:
  has_cpe        -> product data exists (the gap this project measures)
  has_nist_cvss  -> NIST itself scored it (source "nvd@nist.gov")
  has_any_cvss   -> anyone scored it (CNA, CISA-ADP, or NIST)
  has_cna_cvss   -> the CNA that assigned the CVE scored it (metric source == the record's sourceIdentifier)
  has_cwe        -> a weakness type was assigned
  in_kev         -> CISA has confirmed exploitation

Usage:
  export NVD_API_KEY=...            # optional; without it NVD allows ~5 requests / 30 s
  python scripts/fetch_sample.py --days 30

Status: runs against the live APIs (first pull Nov 7, 2026; weekly in CI since Nov 8).
Run scripts/kev_enrichment.py and scripts/kev_lag.py after it, then scripts/build_site.py.
"""

import argparse
import json
import os
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pandas as pd
import requests

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
NIST_SOURCE = "nvd@nist.gov"

ROOT = Path(__file__).resolve().parent.parent
RAW = ROOT / "data" / "raw"
OUT = ROOT / "data" / "processed"


def load_dotenv(path=ROOT / ".env"):
    """Read KEY=value lines from .env into the environment without overriding what is already set."""
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8-sig").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


def nvd_date(dt):
    """NVD wants ISO 8601 with milliseconds and an explicit UTC offset."""
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000+00:00")


def fetch_nvd(days):
    """Page through all CVEs published in the window. NVD caps a window at 120 days."""
    if days > 120:
        raise SystemExit("NVD limits one query to 120 days; use --days 120 or less.")
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=days)
    key = os.environ.get("NVD_API_KEY")
    headers = {"apiKey": key} if key else {}
    pause = 0.7 if key else 6.5  # stay under NVD's published rate limits

    vulns, start_index = [], 0
    while True:
        params = {
            "pubStartDate": nvd_date(start),
            "pubEndDate": nvd_date(end),
            "resultsPerPage": 2000,
            "startIndex": start_index,
        }
        r = get_with_retry(NVD_URL, params=params, headers=headers)
        page = r.json()
        vulns.extend(page.get("vulnerabilities", []))
        total = page.get("totalResults", 0)
        start_index += page.get("resultsPerPage", 0)
        print(f"NVD: {len(vulns)}/{total}")
        if start_index >= total or not page.get("resultsPerPage"):
            break
        time.sleep(pause)
    return vulns, start, end


FLOODLINE_URL = "https://raw.githubusercontent.com/RogoLabs/cvefloodline.org/main/data/floodline.json"


def fetch_floodline():
    """Summarize CVE Floodline (RogoLabs, Apache-2.0) rather than rebuild it.

    Floodline re-scores each day's CVE cohort against the dated EPSS archive at day 0, 7, 30 and 90.
    We take one number from it: the share of CVEs that have crossed EPSS 10% (and 50%) by day 30,
    over cohorts old enough to have a day-30 score. That is the rate at which an EPSS re-check
    trigger would fire on new CVEs. Returns None if the fetch fails, so the page can say so.
    """
    try:
        r = requests.get(FLOODLINE_URL, timeout=60)
        r.raise_for_status()
        d = r.json()
    except Exception as e:  # network or shape problems are reported, never silently zeroed
        print(f"Floodline: unavailable ({e})")
        return None
    days = d.get("days") or []
    elig = [x for x in days if (x.get("maturation") or {}).get("30")]
    if not elig:
        return None
    total = sum(x["total"] for x in elig)
    cells = lambda h: [x["maturation"][h] for x in elig if (x.get("maturation") or {}).get(h)]
    cross = lambda h, t: sum(c["thresholds"].get(str(t), 0) for c in cells(h))
    return {
        "source": "CVE Floodline, RogoLabs (cvefloodline.org), Apache-2.0; data from the FIRST EPSS archive, CISA KEV, and cvelistV5",
        "generated": d.get("generated"),
        "window": [days[0]["date"], days[-1]["date"]] if days else None,
        "epss_model_version": d.get("latest_epss_model_version"),
        "cohorts_with_30d_score": len(elig),
        "cves_with_30d_score": total,
        "cross10_day0": cross("0", 10),
        "cross10_day7": cross("7", 10),
        "cross10_day30": cross("30", 10),
        "cross50_day30": cross("30", 50),
        "share_cross10_day30_pct": round(100 * cross("30", 10) / total, 3),
        "share_cross50_day30_pct": round(100 * cross("30", 50) / total, 3),
        "mean_net_cves_per_day": round(sum(x["net_total"] for x in days) / len(days), 1),
        "kev_in_window": sum(x.get("kev", 0) for x in days),
        "note": "Crossings count EPSS strictly above the threshold on the dated file at day+30; a point-in-time count that includes CVEs already with CPE and excludes the older unenriched stock, so it is rough and biased both ways, not a lower bound (see docs/research/notes/open_items_recheck_volume.md).",
    }


def fetch_kev():
    r = requests.get(KEV_URL, timeout=60)
    r.raise_for_status()
    return {v["cveID"]: v.get("dateAdded") for v in r.json().get("vulnerabilities", [])}


def get_with_retry(url, attempts=5, **kwargs):
    """GET with exponential backoff; the public APIs return 429/5xx under load."""
    for attempt in range(attempts):
        try:
            r = requests.get(url, timeout=60, **kwargs)
            if r.status_code in (429, 500, 502, 503, 504) and attempt < attempts - 1:
                raise requests.HTTPError(f"{r.status_code} from {url}")
            r.raise_for_status()
            return r
        except (requests.HTTPError, requests.ConnectionError, requests.Timeout) as e:
            if attempt == attempts - 1:
                raise
            wait = 2 ** attempt * 3
            print(f"retry {attempt + 1}/{attempts - 1} after {wait}s: {str(e)[:80]}")
            time.sleep(wait)


def fetch_epss(cve_ids, batch=100):
    """FIRST's API accepts a comma-separated list of CVEs per request."""
    scores = {}
    for i in range(0, len(cve_ids), batch):
        chunk = cve_ids[i:i + batch]
        r = get_with_retry(EPSS_URL, params={"cve": ",".join(chunk)})
        for row in r.json().get("data", []):
            scores[row["cve"]] = float(row["epss"])
        time.sleep(0.2)
    return scores


PLACEHOLDERS = {"n/a", "na", "", "none", "unknown", "-", "unspecified"}


def cna_names_product(cve):
    """True when the CNA's own 'affected' block names a real vendor and product (free text, not CPE)."""
    for block in cve.get("affected") or []:
        for item in block.get("affectedData") or []:
            vendor = (item.get("vendor") or "").strip().lower()
            product = (item.get("product") or "").strip().lower()
            if vendor not in PLACEHOLDERS and product not in PLACEHOLDERS:
                return True
    return False


def flags_for(vuln):
    """Turn one NVD record into the yes/no flags this project measures."""
    cve = vuln["cve"]
    metrics = cve.get("metrics", {})
    all_scores = [m for key in metrics for m in metrics[key]]  # cvssMetricV40, V31, V30, V2
    return {
        "cve_id": cve["id"],
        "published": cve.get("published"),
        "last_modified": cve.get("lastModified"),
        "vuln_status": cve.get("vulnStatus"),
        "has_cpe": bool(cve.get("configurations")),
        "has_nist_cvss": any(m.get("source") == NIST_SOURCE for m in all_scores),
        "has_any_cvss": bool(all_scores),
        "has_cna_cvss": any(m.get("source") == cve.get("sourceIdentifier") for m in all_scores),
        "has_cwe": bool(cve.get("weaknesses")),
        "cna_names_product": cna_names_product(cve),
        "nvd_kev_date": cve.get("cisaExploitAdd"),
    }


# NVD API status values and the labels NIST shows on nvd.nist.gov (status page updated Apr 14, 2026).
STATUS_LABELS = {
    "Received": "Received",
    "Awaiting Analysis": "Awaiting Enrichment",
    "Undergoing Analysis": "Undergoing Enrichment",
    "Analyzed": "Enriched",
    "Modified": "Modified After Enrichment",
    "Deferred": "Not Scheduled",
    "Rejected": "Rejected",
}


def summarize(df):
    """Two denominators, both explicit: all CVEs in the window, and CVEs excluding Rejected ('live')."""
    n = len(df)
    live = df[df["vuln_status"] != "Rejected"]
    n_live = len(live)
    pct = lambda frame, col: round(100 * frame[col].mean(), 1) if len(frame) else None

    # Crude time to enrichment: lastModified - published for Enriched (Analyzed) CVEs, in days.
    enriched = live[live["vuln_status"] == "Analyzed"]
    days = (pd.to_datetime(enriched["last_modified"]) - pd.to_datetime(enriched["published"])).dt.total_seconds() / 86400
    tte = {
        "n": int(len(days)),
        "median_days": round(float(days.median()), 1) if len(days) else None,
        "p90_days": round(float(days.quantile(0.9)), 1) if len(days) else None,
        "caveat": "lastModified minus published for Enriched CVEs only; right-censored by the window and inflated by later edits.",
    }

    statuses = []
    for status, count in live["vuln_status"].value_counts().items():
        sub = live[live["vuln_status"] == status]
        statuses.append({
            "api_status": status,
            "label": STATUS_LABELS.get(status, status),
            "count": int(count),
            "pct_of_live": round(100 * count / n_live, 1),
            "pct_with_cpe": pct(sub, "has_cpe"),
            "pct_cna_names_product": pct(sub, "cna_names_product"),
        })

    no_cpe_not_kev = live[~live["has_cpe"] & ~live["in_kev"]]
    epss_tiers = {f"ge_{t:.2f}": int((no_cpe_not_kev["epss"] >= t).sum()) for t in (0.01, 0.05, 0.10, 0.50)}
    # No score yet (missing, or exactly 0), in the same group as the tiers. Until Nov 9, 2026 this was counted over
    # every record as epss_missing_or_zero; Rejected records never get a score, so that count was about six times
    # too high for "no score yet" (Nov 7 pull: 787, of which 659 Rejected and 128 in this group).
    epss_tiers["unscored"] = int((no_cpe_not_kev["epss"] == 0).sum())

    return {
        "cves_in_window": n,
        "rejected": int(n - n_live),
        "cves_live": n_live,
        "pct_with_cpe": pct(df, "has_cpe"),
        "with_cpe_live": int(live["has_cpe"].sum()),
        "pct_with_cpe_live": pct(live, "has_cpe"),
        "pct_with_nist_cvss": pct(df, "has_nist_cvss"),
        "pct_with_nist_cvss_live": pct(live, "has_nist_cvss"),
        "pct_with_any_cvss": pct(df, "has_any_cvss"),
        "pct_with_any_cvss_live": pct(live, "has_any_cvss"),
        "pct_with_cna_cvss_live": pct(live, "has_cna_cvss"),   # the rest of "any" is mostly CISA-ADP (Vulnrichment)
        "pct_with_cwe": pct(df, "has_cwe"),
        "pct_cna_names_product_live": pct(live, "cna_names_product"),
        "pct_cna_product_but_no_cpe_live": round(100 * (live["cna_names_product"] & ~live["has_cpe"]).mean(), 1) if n_live else None,
        "in_kev": int(df["in_kev"].sum()),
        "in_kev_with_cpe": int((df["in_kev"] & df["has_cpe"]).sum()),
        "pct_cpe_if_in_kev": pct(df[df["in_kev"]], "has_cpe"),
        "pct_cpe_if_not_in_kev": pct(live[~live["in_kev"]], "has_cpe"),
        "epss_ge_0_10_without_cpe": int(((df["epss"] >= 0.10) & ~df["has_cpe"]).sum()),
        "epss_ge_0_50_without_cpe": int(((df["epss"] >= 0.50) & ~df["has_cpe"]).sum()),
        "epss_without_cpe_not_kev": epss_tiers,
        "time_to_enrichment": tte,
        "status_counts": df["vuln_status"].value_counts().to_dict(),
        "statuses": statuses,
    }


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--days", type=int, default=30)
    p.add_argument("--from-raw", action="store_true",
                   help="reprocess data/raw/nvd_sample.json instead of calling the NVD API (KEV and EPSS are still fetched)")
    args = p.parse_args()
    load_dotenv()
    RAW.mkdir(parents=True, exist_ok=True)
    OUT.mkdir(parents=True, exist_ok=True)

    if args.from_raw:
        vulns = json.loads((RAW / "nvd_sample.json").read_text())
        pubs = [v["cve"]["published"] for v in vulns]
        start, end = pd.Timestamp(min(pubs), tz="UTC"), pd.Timestamp(max(pubs), tz="UTC")
        print(f"Reprocessing {len(vulns)} raw records ({start.date()} to {end.date()})")
    else:
        print("NVD API key:", "found" if os.environ.get("NVD_API_KEY") else "not set (slow mode)")
        vulns, start, end = fetch_nvd(args.days)
        (RAW / "nvd_sample.json").write_text(json.dumps(vulns))
    kev = fetch_kev()
    df = pd.DataFrame([flags_for(v) for v in vulns])
    if df.empty:
        raise SystemExit("No CVEs returned; check the date window and API response.")
    df["kev_date_added"] = df["cve_id"].map(kev)
    df["in_kev"] = df["kev_date_added"].notna()
    df["epss"] = df["cve_id"].map(fetch_epss(df["cve_id"].tolist())).fillna(0.0)

    df.to_csv(OUT / "cves_sample.csv", index=False)
    summary = summarize(df)
    summary["floodline"] = fetch_floodline()
    summary["window_utc"] = [start.isoformat(), end.isoformat()]
    summary["pulled_at_utc"] = datetime.now(timezone.utc).isoformat()
    (OUT / "summary.json").write_text(json.dumps(summary, indent=2))
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
