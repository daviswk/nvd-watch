"""
build_site.py — render the scorecard page from processed data.

Reads  data/processed/summary.json; data/processed/cves_sample.csv only as a cross-check, when it is from the
       same pull (it is git-ignored, so it lags after a weekly bot commit)
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

import cost_model as cm   # the re-check cost rule; site/cost.js mirrors it

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


def short_date(iso):
    d = datetime.fromisoformat(iso)
    return f"{d:%b} {d.day}"


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


def kev_lag_figure(lag):
    """Section 2 chart, its text alternative, the caption's date note, and the highlight sentence,
    all from data/processed/kev_lag.json (scripts/kev_lag.py). Nothing here is typed by hand.

    The longest bar is always 300 px, so a rise can't run off the chart. The sentence lists the
    medians without a trend verb, so a rebuild can't make it claim a rise the data no longer shows."""
    years = sorted(lag["by_year"])
    through = datetime.fromisoformat(lag["through"])
    partial = years[-1] == str(through.year)            # the current year is incomplete
    med = {y: lag["by_year"][y]["median_days"] for y in years}
    days = lambda d: f"{d:g} day" + ("" if d == 1 else "s")
    through_md = f"{through:%B} {through.day}"
    label = lambda y: f"{y} to {through_md}" if (partial and y == years[-1]) else y

    step, top, bar_h, x0, longest = 38, 20, 24, 60, 300
    scale = longest / max(max(med.values()), 1)
    axis_end = 12 + step * len(years) + 2
    labels, bars = [], []
    for i, y in enumerate(years):
        w = round(med[y] * scale)
        labels.append(f'<text x="0" y="{top + 16 + step * i}">{y}</text>')
        bars.append(f'            <rect class="bar" x="{x0}" y="{top + step * i}" width="{w}" height="{bar_h}"/>'
                    f'<text class="val" x="{x0 + w + 8}" y="{top + 17 + step * i}">{days(med[y])}</text>')
    desc = " ".join(f"{label(y)}: {days(med[y])}." for y in years)
    svg = "\n".join([
        f'          <svg viewBox="0 0 560 {axis_end + 24}" role="img" aria-labelledby="chart-title chart-desc">',
        '            <title id="chart-title">Median CVE-to-KEV lag by year</title>',
        f'            <desc id="chart-desc">{desc} Computed by NVD Watch from the CISA KEV feed and NVD publication dates.</desc>',
        '            <g class="lbl">',
        "              " + "".join(labels),
        "            </g>",
        f'            <line class="axis" x1="{x0}" y1="12" x2="{x0}" y2="{axis_end}"/>',
        *bars,
        "          </svg>",
    ])

    parts = [f"{days(med[years[0]])} in {years[0]}"] + [f"{med[y]:g} in {y}" for y in years[1:]]
    if partial:
        parts[-1] = f"{med[years[-1]]:g} so far in {years[-1]}"
    listed = parts[0] if len(parts) == 1 else ", ".join(parts[:-1]) + ", and " + parts[-1]
    sentence = f"By our count, the median lag from CVE publication to a KEV listing was {listed}."
    note = f"{years[-1]} is through {through_md}." if partial else ""
    return svg, sentence, note


def kev_lag_in_window(k):
    """Median days from NVD publication to KEV listing for KEV CVEs published in the window.
    k: rows with `published` and `kev_date_added` (the CSV's in_kev rows, or kev_enrichment.json's sample rows)."""
    if k.empty:
        return None, 0
    pub = pd.to_datetime(k["published"].str[:10])
    added = pd.to_datetime(k["kev_date_added"])
    lag = (added - pub).dt.days
    return float(lag.median()), int(len(lag))


def load_csv_if_current(summary):
    """The per-CVE CSV, or None if it is missing or from another pull.

    The weekly workflow commits summary.json but cves_sample.csv is git-ignored, so after a bot commit the
    local CSV belongs to an older pull. It matches this summary only if it has the same number of CVEs and
    every publication date falls inside summary.json's window."""
    path = PROCESSED / "cves_sample.csv"
    if not path.exists():
        print("WARNING: data/processed/cves_sample.csv not found; skipping the CSV cross-check.")
        return None
    df = pd.read_csv(path)
    start, end = (pd.Timestamp(w).tz_localize(None) for w in summary["window_utc"])
    pub = pd.to_datetime(df["published"])
    if len(df) != summary["cves_in_window"] or pub.min() < start or pub.max() > end:
        print(f"WARNING: cves_sample.csv is from another pull ({len(df):,} CVEs published {pub.min():%Y-%m-%d} to "
              f"{pub.max():%Y-%m-%d}; summary.json has {summary['cves_in_window']:,}, window "
              f"{start:%Y-%m-%d} to {end:%Y-%m-%d}, pulled {summary['pulled_at_utc'][:16]} UTC). Skipping the CSV "
              "cross-check; KEV lag in the window comes from kev_enrichment.json. Run fetch_sample.py to refresh it.")
        return None
    return df


def main():
    load_dotenv()
    summary = json.loads((PROCESSED / "summary.json").read_text())
    df = load_csv_if_current(summary)   # None when the local CSV lags a bot commit of summary.json

    pulled = datetime.fromisoformat(summary["pulled_at_utc"])
    age_days = (datetime.now(timezone.utc) - pulled).days
    window_start, window_end = summary["window_utc"]
    by_status = {s["api_status"]: s for s in summary["statuses"]}
    deferred = by_status.get("Deferred", {"count": 0, "pct_of_live": 0})
    awaiting = by_status.get("Awaiting Analysis", {"count": 0, "pct_of_live": 0})
    enriched = by_status.get("Analyzed", {"count": 0})
    tiers = summary["epss_without_cpe_not_kev"]
    tte = summary["time_to_enrichment"]
    # Counted by the pipeline, never back-derived from a rounded percentage. The CSV count is a cross-check,
    # run only when the CSV is from the same pull as summary.json.
    n_cpe_live = int(summary["with_cpe_live"])
    if df is not None:
        live = df[df["vuln_status"] != "Rejected"]
        if n_cpe_live != int(live["has_cpe"].sum()):
            sys.exit(f"summary.json with_cpe_live={n_cpe_live} disagrees with the CSV ({int(live['has_cpe'].sum())}); re-run fetch_sample.py")

    # Canonical URL for the static citation (JS-off and print). Set SITE_URL in .env or the environment
    # once the page is deployed; until then the citation carries no URL rather than a placeholder.
    site_url = os.environ.get("SITE_URL", "").strip()
    site_url_line = f' Available at <a href="{escape(site_url)}">{escape(site_url)}</a>.' if site_url else ""

    # Re-check volume, measured once from the whole NVD stock (scripts/research/recheck_volume.py plus an
    # NVD change-history check; see docs/research/notes/open_items_recheck_volume.md). Not rebuilt weekly,
    # so the page dates it. The simulator default is the highest month observed.
    fl = summary.get("floodline")   # still used for the score-maturation paragraph in section 2
    rm_path = PROCESSED / "recheck_measured.json"
    if not rm_path.exists():
        sys.exit("data/processed/recheck_measured.json missing; see docs/research/notes/open_items_recheck_volume.md")
    rm = json.loads(rm_path.read_text())
    monthly = [w["requeues"] for w in rm["monthly_flow"]["windows"]]
    rq_lo, rq_hi = min(monthly), max(monthly)
    t_pct = f"{cm.half_up(100 * rm['threshold'])}%"     # the rule's threshold (EPSS 0.05 since Nov 8)
    one_time = rm["one_time_load"][rm["threshold_key"]]
    win = rm["monthly_flow"]["windows"]
    monthly_10 = [w["requeues"] for w in rm["monthly_flow_0_10"]["windows"]]   # shown for comparison
    old_n, old_of = rm["monthly_flow"]["published_over_90_days_before_crossing"]
    requeue_default = rq_hi
    requeue_source = (
        f"we counted it from the whole NVD stock on {fmt_date(rm['measured_on'])}. Of the "
        f"{fmt_int(rm['stock']['total'])} CVEs without CPE in Not Scheduled, Awaiting Enrichment or Received, none "
        f"in KEV, {fmt_int(one_time)} already score EPSS {t_pct} or higher: a one-time load. After that, "
        f"{rq_lo} to {rq_hi} a month crossed {t_pct} before they had CPE, in four 30-day windows from "
        f"{fmt_date(win[0]['from'])} to {fmt_date(win[-1]['to'])} (NVD change history included). {old_n} of the "
        f"{old_of} that were still without CPE had been published more than 90 days before crossing. "
        f"The default below is the highest month. The count leaves out the LEV, SSVC and third-party triggers, "
        f"which would add to it, and covers five months under one EPSS model (v5, from June 15, 2026)."
    )

    # Orphaned CVEs (scripts/research/osv_orphans.py): no CPE and no open package advisory in OSV.
    # A research run over ~3 GB of OSV exports, not part of the weekly pull, so it is shown only while it
    # describes the same window as summary.json; after a new pull the row and its paragraph drop out.
    orphan_row = orphan_para = osv_source_li = ""
    op_path = PROCESSED / "osv_orphans.json"
    if op_path.exists():
        op = json.loads(op_path.read_text())
        if op["window"] == f"{window_start[:10]} to {window_end[:10]}":
            o, nc = op["orphans"], op["without_cpe"]
            orphan_row = (
                "<tr class=\"sub\">"
                "<th scope=\"row\">No CPE and no open package advisory <span class=\"api\">All statuses; "
                f"OSV, {short_date(op['run_date'])}</span></th>"
                f"<td class=\"num\" data-label=\"CVEs\">{fmt_int(o['n'])}</td>"
                f"<td class=\"num\" data-label=\"Share\">{fmt_pct(o['pct_of_live'])}</td>"
                "<td class=\"num\" data-label=\"With CPE\">0%</td>"
                f"<td class=\"num\" data-label=\"CNA names a product\">{fmt_pct(o['pct_cna_names_product'])}</td>"
                "</tr>"
            )
            ns = op["without_cpe_by_status"].get("Deferred")
            orphan_para = (
                "<p><b>Package advisories fill only part of the gap.</b> Of the "
                f"{fmt_int(nc['n'])} CVEs without CPE, {fmt_int(nc['language'])} appear in an open-source package "
                f"advisory (npm, PyPI, Go and others) and {fmt_int(nc['distro'])} only in Linux distribution "
                f"advisories, as OSV aggregates them. The other {fmt_int(nc['none'])} ({fmt_pct(nc['pct_none'])}) "
                "have neither, so a scanner has no CPE and no package name to match on"
                + (f"; among Not Scheduled CVEs the share is {fmt_pct(ns['pct_none'])}" if ns else "")
                + ". They are mostly enterprise products, WordPress components and small open-source projects. "
                "<span class=\"note\">Open advisories only; vendor bulletins are not counted, and the share falls "
                "as late advisories arrive. Data: <a href=\"data/osv_orphans.json\">osv_orphans.json</a>.</span></p>"
            )
            osv_source_li = (
                "      <li>OSV.dev (Google), <a href=\"https://google.github.io/osv.dev/data/\">open-source "
                "vulnerability database exports</a>, all package ecosystems except GIT, downloaded "
                f"{fmt_date(op['run_date'])}. The section 1 orphan count is ours "
                "(<a href=\"data/osv_orphans.json\">osv_orphans.json</a>).</li>"
            )
            (SITE / "data").mkdir(exist_ok=True)
            shutil.copy(op_path, SITE / "data" / "osv_orphans.json")
        else:
            print(f"note: osv_orphans.json is for {op['window']}, not this pull; orphan row left out", file=sys.stderr)
    if not orphan_row:
        # Don't publish a file the page no longer uses or cites.
        (SITE / "data" / "osv_orphans.json").unlink(missing_ok=True)

    # Every figure and sentence of the estimate comes from cost_model; site/cost.js recomputes the
    # same strings in the browser from the model written into the page.
    sim = cm.outputs(requeue_default, one_time=one_time)
    once_lo = cm.outputs(0, minutes=min(cm.MINUTES), one_time=one_time)["once"]
    once_hi = cm.outputs(0, minutes=max(cm.MINUTES), one_time=one_time)["once"]
    rq_window_rows = "\n".join(
        "<tr>"
        f"<th scope=\"row\">{short_date(w['from'])} to {short_date(w['to'])}</th>"
        f"<td class=\"num\" data-label=\"Still no CPE\">{w['stock_crossers']}</td>"
        f"<td class=\"num\" data-label=\"Got CPE later\">{w['enriched_after_crossing']}</td>"
        f"<td class=\"num\" data-label=\"Re-queues\"><b>{w['requeues']}</b></td>"
        "</tr>"
        for w in win
    )

    # Section 2 chart and the highlight's lag sentence (scripts/kev_lag.py).
    lag_path = PROCESSED / "kev_lag.json"
    if not lag_path.exists():
        sys.exit("data/processed/kev_lag.json missing; run scripts/kev_lag.py before build_site.py")
    lag = json.loads(lag_path.read_text())
    kev_lag_svg, kev_lag_sentence, kev_lag_through_note = kev_lag_figure(lag)

    # Legacy share (scripts/kev_lag.py): of each year's KEV additions, the share NVD published 4+ years
    # before the listing. Latest year in full, earlier years for comparison, no trend verb.
    ly = lag.get("legacy_by_year")
    if not ly:
        sys.exit("kev_lag.json has no legacy_by_year; re-run scripts/kev_lag.py")
    ly_years = sorted(ly)
    last = ly[ly_years[-1]]
    legacy_sentence = (
        f"<b>Old flaws are still being exploited.</b> Of the {fmt_int(last['n'])} CVEs CISA added to KEV in "
        f"{ly_years[-1]} through {fmt_date(lag['through'])}, {last['published_4y_before']} "
        f"({fmt_pct(last['pct'])}) had been published four or more years before the listing ("
        + "; ".join(f"{y}: {fmt_pct(ly[y]['pct'])}" for y in ly_years[:-1])
        + "). <span class=\"note\">CVE age, not code age: see Definitions. Data: "
        "<a href=\"data/kev_lag.json\">kev_lag.json</a>.</span>"
    )

    # Readiness (metric 1) and the KEV goal (metric 4), from NVD change history (scripts/kev_enrichment.py).
    # "When defenders need it" = by the day CISA confirms exploitation (KEV listing).
    ke_path = PROCESSED / "kev_enrichment.json"
    if not ke_path.exists():
        sys.exit("data/processed/kev_enrichment.json missing; run scripts/kev_enrichment.py after fetch_sample.py")
    ke = json.loads(ke_path.read_text())
    if ke["kev_cves"] != summary["in_kev"]:
        sys.exit(f"kev_enrichment.json covers {ke['kev_cves']} KEV CVEs, summary.json has {summary['in_kev']}; re-run kev_enrichment.py")
    # KEV lag for CVEs published in the window: from the CSV when it is current, else from kev_enrichment.json's
    # sample rows (same CVEs, same publication and KEV dates; committed by the weekly workflow).
    kev_rows = (df[df["in_kev"]] if df is not None
                else pd.DataFrame([r for r in ke["rows"] if r["in_sample"]], columns=["published", "kev_date_added"]))
    kev_lag_median, kev_lag_n = kev_lag_in_window(kev_rows)
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

    # While a listed CVE has no CPE yet, it is neither a hit nor a miss: say "x of y resolved, z pending".
    ke_pending_n = kl["kev_cves"] - kl["with_cpe_now"]
    if ke_pending_n:
        ke_l_goal = f"{fmt_int(kl['within_one_business_day'])} of {fmt_int(kl['with_cpe_now'])} resolved, {fmt_int(ke_pending_n)} pending"
        ke_l_goal_sentence = (f"{fmt_int(kl['within_one_business_day'])} of the {fmt_int(kl['with_cpe_now'])} with CPE so far "
                              f"had it within one business day ({fmt_int(ke_pending_n)} still pending)")
    else:
        ke_l_goal = f"{fmt_int(kl['within_one_business_day'])} of {fmt_int(kl['kev_cves'])}"
        ke_l_goal_sentence = f"{ke_l_goal} had CPE within one business day"

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
        "pct_cna_cvss_live": fmt_pct(summary["pct_with_cna_cvss_live"]),   # added Nov 7; older summaries lack it
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
        "orphan_row": orphan_row,
        "orphan_para": orphan_para,
        "stale_notice": stale_notice,
        "site_url_line": site_url_line,
        "requeue_default": fmt_int(requeue_default),
        "requeue_default_num": str(requeue_default),
        "requeue_source": requeue_source,
        "rq_lo": str(rq_lo),
        "rq_hi": str(rq_hi),
        "rq_one_time": fmt_int(one_time),
        "rq_one_time_share": f"{cm.half_up(100 * one_time / cm.CAPACITY_PER_MONTH)}%",
        "rq_one_time_cost": f"{once_lo} to {once_hi}",
        "rq_measured_on": fmt_date(rm["measured_on"]),
        "rq_one_time_num": str(one_time),
        "rq_window_rows": rq_window_rows,
        "sim_once": sim["once"],
        "rq_t_pct": t_pct,
        "rq_one_time_10": fmt_int(rm["one_time_load"]["t_0_10"]),
        "rq_lo_10": str(min(monthly_10)),
        "rq_hi_10": str(max(monthly_10)),
        "rq_one_time_01": fmt_int(rm["one_time_load"]["t_0_01"]),
        "fl_share10": f"{fl['share_cross10_day30_pct']:g}%" if fl else "n/a",
        "fl_share50": f"{fl['share_cross50_day30_pct']:g}%" if fl else "n/a",
        "fl_cross10_day0": fmt_int(fl["cross10_day0"]) if fl else "n/a",
        "fl_cross10_day7": fmt_int(fl["cross10_day7"]) if fl else "n/a",
        "fl_cross10_day30": fmt_int(fl["cross10_day30"]) if fl else "n/a",
        "fl_n": fmt_int(fl["cves_with_30d_score"]) if fl else "n/a",
        "fl_generated": fmt_date(fl["generated"]) if fl else "n/a",
        "sim_hours": sim["hours"],
        "sim_capacity": sim["capacity"],
        "sim_cost": sim["cost"],
        "sim_low_high": sim["low_high"],
        "sim_offset": sim["offset"],
        "sim_sentence": sim["sentence"],
        "cost_model_json": cm.page_json(),
        "cm_capacity": cm.num(cm.CAPACITY_PER_MONTH),
        "cm_oig_short": cm.money(cm.OIG_PER_YEAR),
        "cm_oig_full": f"${cm.num(cm.OIG_PER_YEAR)}",
        "cm_rate": str(cm.RATE),
        "cm_minutes_lo": str(min(cm.MINUTES)),
        "cm_minutes_hi": str(max(cm.MINUTES)),
        "cm_minutes_radios": "\n".join(
            f'                <label><input type="radio" name="minutes" value="{m}"'
            f'{" checked" if m == cm.DEFAULT_MINUTES else ""}><span>{m}</span></label>' for m in cm.MINUTES),
        "ke_l_n": fmt_int(kl["kev_cves"]),
        "ke_l_goal": ke_l_goal,
        "ke_l_goal_sentence": ke_l_goal_sentence,
        "osv_source_li": osv_source_li,
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
        "kev_lag_svg": kev_lag_svg,
        "kev_lag_sentence": kev_lag_sentence,
        "legacy_sentence": legacy_sentence,
        "kev_lag_through_note": kev_lag_through_note,
    }

    template = (SITE / "template.html").read_text(encoding="utf-8")
    missing = sorted(set(re.findall(r"{{(\w+)}}", template)) - set(values))
    if missing:
        sys.exit(f"template tokens with no value: {', '.join(missing)}")
    html = re.sub(r"{{(\w+)}}", lambda m: values[m.group(1)], template)
    (SITE / "index.html").write_text(html, encoding="utf-8")

    (SITE / "data").mkdir(exist_ok=True)
    shutil.copy(PROCESSED / "summary.json", SITE / "data" / "summary.json")
    shutil.copy(lag_path, SITE / "data" / "kev_lag.json")   # also read by the story page
    (SITE / "data" / "cost_model.json").write_text(json.dumps(cm.MODEL, indent=2))   # read by story.js
    shutil.copy(ke_path, SITE / "data" / "kev_enrichment.json")   # the per-CVE evidence behind metrics 1 and 4
    shutil.copy(rm_path, SITE / "data" / "recheck_measured.json")  # read by the story page

    # Keep each pull's figures, keyed by pull date, so week-to-week stability can be checked
    # (scripts/stability.py). Rebuilding from the same pull overwrites the same folder.
    hist = ROOT / "data" / "history" / pulled.strftime("%Y-%m-%d")
    hist.mkdir(parents=True, exist_ok=True)
    shutil.copy(PROCESSED / "summary.json", hist / "summary.json")
    shutil.copy(ke_path, hist / "kev_enrichment.json")
    print(f"wrote site/index.html from data pulled {values['pulled_at']} ({values['n_total']} CVEs)")


if __name__ == "__main__":
    main()
