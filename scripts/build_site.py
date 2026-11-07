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
    hi = live[live["epss"] >= 0.10]
    hi_n = int(len(hi))
    hi_kev = int(hi["in_kev"].sum())
    hi_out = hi[~hi["in_kev"]]
    hi_out_n, hi_out_nocpe = int(len(hi_out)), int((~hi_out["has_cpe"]).sum())
    fl = summary.get("floodline")
    if fl:
        share10 = fl["share_cross10_day30_pct"] / 100
        requeue_default = max(1, int(round(summary["cves_live"] * share10)))
        requeue_source = (
            f"CVE Floodline: {fmt_int(fl['cross10_day30'])} of {fmt_int(fl['cves_with_30d_score'])} CVEs "
            f"published {fmt_date(fl['window'][0])} to {fmt_date(fl['window'][1])} crossed EPSS 10% by day 30 "
            f"({fl['share_cross10_day30_pct']:g}%), applied to our {fmt_int(summary['cves_live'])} CVEs per 30 days. "
            f"It is a rough estimate, and its biases run both ways. Floodline counts every CVE that crosses, "
            f"including ones CISA has already listed: in our window, {hi_kev} of the {hi_n} CVEs at EPSS 10% or higher "
            f"are in KEV, and EPSS tends to rise after a KEV listing (Nucleus Security), so those need no re-check. "
            f"That pushes the count down. Of the {hi_out_n} outside KEV, {hi_out_nocpe} have no CPE. The estimate also "
            f"misses crossings after day 30, the older Not Scheduled stock, and SSVC or third-party triggers, which "
            f"push it up."
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
    # Scale comparison only (same wording as app.js): NIST already stopped routine re-scoring in
    # April 2026 and moved that capacity to triage, so the OIG figure is not unspent money.
    share = f"about {round(100 * ratio)}% of" if ratio <= 1 else f"about {round(ratio, 1):g} times"
    verdict = (f"{share} the value of the routine re-scoring NIST stopped in April 2026 (the Commerce OIG put it at "
               "roughly $400K a year; NIST disputes the figure). That capacity already went to triage, so this "
               "compares scale; it is not spare money")
    sim_sentence = (
        f"Re-checking <b>{fmt_int(requeue_default)} CVEs a month</b> at 45 analyst-minutes each takes about "
        f"<b>{fmt_int(h_mid)} analyst-hours a year</b>, {cap:.1f}% of NIST's peak monthly output, and costs about "
        f"<b>{money(c_mid)} a year</b> at $120 an hour: {verdict}."
    )

    # Harm metric and metric 3, from NVD change history (scripts/kev_enrichment.py).
    # "When defenders need it" = by the day CISA confirms exploitation (KEV listing).
    ke_path = PROCESSED / "kev_enrichment.json"
    if not ke_path.exists():
        sys.exit("data/processed/kev_enrichment.json missing; run scripts/kev_enrichment.py after fetch_sample.py")
    ke = json.loads(ke_path.read_text())
    if ke["kev_cves"] != summary["in_kev"]:
        sys.exit(f"kev_enrichment.json covers {ke['kev_cves']} KEV CVEs, summary.json has {summary['in_kev']}; re-run kev_enrichment.py")
    pending = [r for r in ke["rows"] if not r["first_cpe"]]
    kev_pending_note = (
        "" if not pending else
        " " + ("; ".join(f"{r['cve_id']} (listed {fmt_date(r['kev_date_added'])})" for r in pending))
        + (" has" if len(pending) == 1 else " have") + " no CPE yet."
    )
    # Claims about NIST's speed are generated from the data so a weekly rebuild can't leave them false.
    # "listed" = every CVE added to KEV in the window, whatever its publication date.
    kl = ke["listed_in_window"]
    met_all = kl["within_one_business_day"] == kl["with_cpe_now"]
    ke_headline = ("Once CISA confirms an attack, NIST moves fast. Before that, it mostly waits." if met_all else
                   "Even after CISA confirms an attack, NIST sometimes misses its own goal.")
    ke_verdict = ("NIST meets its goal once a CVE is listed. The gap is the wait before the listing." if met_all else
                  f"{kl['with_cpe_now'] - kl['within_one_business_day']} took longer than one business day.")

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
        "ke_l_n": fmt_int(kl["kev_cves"]),
        "ke_l_1bd": fmt_int(kl["within_one_business_day"]),
        "ke_l_pub": fmt_int(kl["triage_public_before_kev"]),
        "ke_l_sameday": fmt_int(kl["kev_cves"] - kl["public_before_kev"]),
        "ke_l_pretriage": fmt_int(kl["public_before_kev"] - kl["triage_public_before_kev"]),
        "ke_l_ready": fmt_int(kl["triage_cpe_before_kev"]),
        "ke_l_after": fmt_int(kl["triage_cpe_only_after_kev"]),
        "ke_l_2h": fmt_int(kl["triage_cpe_within_2h_of_kev"]),
        "ke_l_maxwait": fmt_int(kl["max_days_public_without_cpe_until_kev"]),
        "ke_pending_note": kev_pending_note,
        "ke_headline": ke_headline,
        "ke_verdict": ke_verdict,
    }

    template = (SITE / "template.html").read_text(encoding="utf-8")
    missing = sorted(set(re.findall(r"{{(\w+)}}", template)) - set(values))
    if missing:
        sys.exit(f"template tokens with no value: {', '.join(missing)}")
    html = re.sub(r"{{(\w+)}}", lambda m: values[m.group(1)], template)
    (SITE / "index.html").write_text(html, encoding="utf-8")

    (SITE / "data").mkdir(exist_ok=True)
    shutil.copy(PROCESSED / "summary.json", SITE / "data" / "summary.json")
    if (PROCESSED / "kev_lag.json").exists():          # read by the 3D figures and the story page
        shutil.copy(PROCESSED / "kev_lag.json", SITE / "data" / "kev_lag.json")
    shutil.copy(ke_path, SITE / "data" / "kev_enrichment.json")   # the per-CVE evidence behind metric 3
    print(f"wrote site/index.html from data pulled {values['pulled_at']} ({values['n_total']} CVEs)")


if __name__ == "__main__":
    main()
