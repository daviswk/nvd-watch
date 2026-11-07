"""
build_site.py — render the scorecard page from processed data.

Reads  data/processed/summary.json and data/processed/cves_sample.csv
Fills  site/template.html  ({{token}} placeholders)
Writes site/index.html and site/data/summary.json

Why render at build time: the page is then correct with JavaScript off, prints as a
report, and every number on it traces to one JSON file produced by fetch_sample.py.
The build fails loudly if a token has no value, so the page never ships a placeholder.

Usage:
  python scripts/build_site.py
"""

import json
import os
import re
import shutil
import sys
from datetime import datetime, timezone
from html import escape
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parent.parent
PROCESSED = ROOT / "data" / "processed"
SITE = ROOT / "site"
STALE_AFTER_DAYS = 10


def fmt_int(n):
    return f"{int(n):,}"


def fmt_pct(x, digits=1):
    return "n/a" if x is None else f"{x:.{digits}f}%"


def fmt_date(iso):
    return datetime.fromisoformat(iso).strftime("%B %d, %Y").replace(" 0", " ")


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


def status_rows(statuses):
    """One table row per NVD status, display label first, API value in a muted span.
    data-label attributes let the stylesheet stack each row into labelled lines on narrow screens."""
    rows = []
    for s in statuses:
        rows.append(
            "<tr>"
            f"<th scope=\"row\">{escape(s['label'])} <span class=\"api\">API: {escape(s['api_status'])}</span></th>"
            f"<td class=\"num\" data-label=\"CVEs\">{fmt_int(s['count'])}</td>"
            f"<td class=\"num\" data-label=\"Share\">{fmt_pct(s['pct_of_live'])}</td>"
            f"<td class=\"num\" data-label=\"With CPE\">{fmt_pct(s['pct_with_cpe'])}</td>"
            f"<td class=\"num\" data-label=\"CNA names a product\">{fmt_pct(s['pct_cna_names_product'])}</td>"
            "</tr>"
        )
    return "\n".join(rows)


def kev_lag_in_window(df):
    """Median days from NVD publication to KEV listing for KEV CVEs published in the window."""
    k = df[df["in_kev"]].copy()
    if k.empty:
        return None, 0
    pub = pd.to_datetime(k["published"]).dt.normalize()
    added = pd.to_datetime(k["kev_date_added"])
    lag = (added - pub).dt.days
    return float(lag.median()), int(len(lag))


def main():
    load_dotenv()
    summary = json.loads((PROCESSED / "summary.json").read_text())
    df = pd.read_csv(PROCESSED / "cves_sample.csv")

    pulled = datetime.fromisoformat(summary["pulled_at_utc"])
    age_days = (datetime.now(timezone.utc) - pulled).days
    window_start, window_end = summary["window_utc"]
    by_status = {s["api_status"]: s for s in summary["statuses"]}
    deferred = by_status.get("Deferred", {"count": 0, "pct_of_live": 0})
    awaiting = by_status.get("Awaiting Analysis", {"count": 0, "pct_of_live": 0})
    enriched = by_status.get("Analyzed", {"count": 0})
    kev_lag_median, kev_lag_n = kev_lag_in_window(df)
    tiers = summary["epss_without_cpe_not_kev"]
    tte = summary["time_to_enrichment"]
    # Counted by the pipeline, never back-derived from a rounded percentage. The CSV count is a cross-check.
    live = df[df["vuln_status"] != "Rejected"]
    n_cpe_live = int(summary.get("with_cpe_live", live["has_cpe"].sum()))
    if n_cpe_live != int(live["has_cpe"].sum()):
        sys.exit(f"summary.json with_cpe_live={n_cpe_live} disagrees with the CSV ({int(live['has_cpe'].sum())}); re-run fetch_sample.py")

    # Canonical URL for the static citation (JS-off and print). Set SITE_URL in .env or the environment
    # once the page is deployed; until then the citation carries no URL rather than a placeholder.
    site_url = os.environ.get("SITE_URL", "").strip()
    site_url_line = f' Available at <a href="{escape(site_url)}">{escape(site_url)}</a>.' if site_url else ""

    # Re-check volume. Rate from CVE Floodline (RogoLabs): share of a day's CVEs that have crossed
    # EPSS 10% by day 30. Volume is our own 30-day live count. Falls back to a flagged assumption.
    fl = summary.get("floodline")
    if fl:
        share10 = fl["share_cross10_day30_pct"] / 100
        requeue_default = max(1, int(round(summary["cves_live"] * share10)))
        requeue_source = (
            f"CVE Floodline: {fmt_int(fl['cross10_day30'])} of {fmt_int(fl['cves_with_30d_score'])} CVEs "
            f"published {fmt_date(fl['window'][0])} to {fmt_date(fl['window'][1])} crossed EPSS 10% by day 30 "
            f"({fl['share_cross10_day30_pct']:g}%), applied to our {fmt_int(summary['cves_live'])} CVEs per 30 days. "
            f"Day 90 not yet observable, so a lower bound."
        )
    else:
        requeue_default = 40
        requeue_source = "CVE Floodline data was unavailable at build time; 40 per month is a placeholder assumption."

    def sim(cves, minutes, rate=120):
        hours = cves * 12 * minutes / 60
        return hours, hours * rate, 100 * cves / 5000

    def money(n):
        return f"${n / 1e6:.2f}".rstrip("0").rstrip(".") + "M" if n >= 1e6 else f"${round(n / 1000):,}K"

    h_mid, c_mid, cap = sim(requeue_default, 45)
    _, c_lo, _ = sim(requeue_default, 20)
    _, c_hi, _ = sim(requeue_default, 60)
    ratio = c_mid / 400000
    verdict = ("within" if ratio <= 1 else f"about {round(100 * (ratio - 1))}% more than") + \
        " the roughly $400K a year (about $800K over two years) the Commerce OIG estimated NIST could save by cutting back re-scoring"
    sim_sentence = (
        f"Re-checking <b>{fmt_int(requeue_default)} CVEs a month</b> at 45 analyst-minutes each takes about "
        f"<b>{fmt_int(h_mid)} analyst-hours a year</b>, {cap:.1f}% of NIST's peak monthly output, and costs about "
        f"<b>{money(c_mid)} a year</b> at $120 an hour: {verdict}."
    )

    stale_notice = ""
    if age_days > STALE_AFTER_DAYS:
        stale_notice = (
            f"<p class=\"notice\" role=\"status\">This page was last rebuilt from data pulled on "
            f"{fmt_date(summary['pulled_at_utc'])}, {age_days} days ago. Figures may be out of date.</p>"
        )

    values = {
        "week_ending": fmt_date(window_end),
        "window_start": fmt_date(window_start),
        "window_end": fmt_date(window_end),
        "pulled_at": pulled.strftime("%Y-%m-%d %H:%M UTC"),
        "pulled_date": pulled.strftime("%Y-%m-%d"),
        "build_year": str(datetime.now(timezone.utc).year),
        "n_total": fmt_int(summary["cves_in_window"]),
        "n_rejected": fmt_int(summary["rejected"]),
        "n_live": fmt_int(summary["cves_live"]),
        "n_cpe_live": fmt_int(n_cpe_live),
        "pct_cpe_live": fmt_pct(summary["pct_with_cpe_live"]),
        "pct_cpe_live_num": f"{summary['pct_with_cpe_live']:.1f}",
        "pct_nist_cvss_live": fmt_pct(summary["pct_with_nist_cvss_live"]),
        "pct_any_cvss_live": fmt_pct(summary["pct_with_any_cvss_live"]),
        "pct_cna_live": fmt_pct(summary["pct_cna_names_product_live"]),
        "pct_cna_no_cpe_live": fmt_pct(summary["pct_cna_product_but_no_cpe_live"]),
        "kev_n": fmt_int(summary["in_kev"]),
        "kev_with_cpe": fmt_int(summary["in_kev_with_cpe"]),
        "pct_cpe_if_in_kev": fmt_pct(summary["pct_cpe_if_in_kev"], 0),
        "pct_cpe_if_not_in_kev": fmt_pct(summary["pct_cpe_if_not_in_kev"]),
        "kev_lag_median": "n/a" if kev_lag_median is None else f"{kev_lag_median:g}",
        "kev_lag_n": fmt_int(kev_lag_n),
        "epss_ge_010": fmt_int(tiers["ge_0.10"]),
        "epss_ge_005": fmt_int(tiers["ge_0.05"]),
        "epss_ge_001": fmt_int(tiers["ge_0.01"]),
        "epss_missing": fmt_int(summary["epss_missing_or_zero"]),
        "tte_median": "n/a" if tte["median_days"] is None else f"{tte['median_days']:g}",
        "tte_p90": "n/a" if tte["p90_days"] is None else f"{tte['p90_days']:g}",
        "tte_n": fmt_int(tte["n"]),
        "not_scheduled_n": fmt_int(deferred["count"]),
        "not_scheduled_pct": fmt_pct(deferred["pct_of_live"]),
        "awaiting_n": fmt_int(awaiting["count"]),
        "awaiting_pct": fmt_pct(awaiting["pct_of_live"]),
        "enriched_n": fmt_int(enriched["count"]),
        "status_rows": status_rows(summary["statuses"]),
        "stale_notice": stale_notice,
        "site_url_line": site_url_line,
        "requeue_default": fmt_int(requeue_default),
        "requeue_default_num": str(requeue_default),
        "requeue_source": requeue_source,
        "fl_share10": f"{fl['share_cross10_day30_pct']:g}%" if fl else "n/a",
        "fl_share50": f"{fl['share_cross50_day30_pct']:g}%" if fl else "n/a",
        "fl_cross10_day0": fmt_int(fl["cross10_day0"]) if fl else "n/a",
        "fl_cross10_day7": fmt_int(fl["cross10_day7"]) if fl else "n/a",
        "fl_cross10_day30": fmt_int(fl["cross10_day30"]) if fl else "n/a",
        "fl_n": fmt_int(fl["cves_with_30d_score"]) if fl else "n/a",
        "fl_generated": fmt_date(fl["generated"]) if fl else "n/a",
        "sim_hours": fmt_int(h_mid),
        "sim_capacity": f"{cap:.1f}%",
        "sim_cost": money(c_mid),
        "sim_low_high": f"{money(c_lo)} to {money(c_hi)}",
        "sim_offset": f"{round(100 * ratio)}%",
        "sim_sentence": sim_sentence,
    }

    template = (SITE / "template.html").read_text(encoding="utf-8")
    missing = sorted(set(re.findall(r"{{(\w+)}}", template)) - set(values))
    if missing:
        sys.exit(f"template tokens with no value: {', '.join(missing)}")
    html = re.sub(r"{{(\w+)}}", lambda m: values[m.group(1)], template)
    (SITE / "index.html").write_text(html, encoding="utf-8")

    (SITE / "data").mkdir(exist_ok=True)
    shutil.copy(PROCESSED / "summary.json", SITE / "data" / "summary.json")
    print(f"wrote site/index.html from data pulled {values['pulled_at']} ({values['n_total']} CVEs)")


if __name__ == "__main__":
    main()
