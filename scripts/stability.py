"""
stability.py — are the small-n KEV figures stable from one weekly pull to the next?

Reads  data/history/YYYY-MM-DD/kev_enrichment.json (written by build_site.py on every build)
Prints readiness (CPE before the KEV listing) and NIST's one-business-day goal, x of n, per pull,
then the min and max share of each.

Why: 10 of 23 and 34 of 35 come from one 30-day window. If they swing between pulls, the brief
should report a range, not a point. Weekly pulls use overlapping 30-day windows: consecutive weeks
share ~23 of 30 days and most of their CVEs, so a narrow min-max across weekly pulls is not evidence
of stability. The script therefore also prints the overlap between consecutive pulls, the range over
non-overlapping windows only (chosen greedily from the earliest pull), and readiness on the union of
every pull's rows (data/history/kev_cumulative.json, written by kev_enrichment.py).

Usage:
  python scripts/stability.py
"""

import json
from datetime import date
from pathlib import Path

HISTORY = Path(__file__).resolve().parent.parent / "data" / "history"


def main():
    rows = []
    for f in sorted(HISTORY.glob("*/kev_enrichment.json")):
        kl = json.loads(f.read_text())["listed_in_window"]
        rows.append((f.parent.name,
                     kl["triage_cpe_before_kev"], kl["triage_public_before_kev"],
                     kl["within_one_business_day"], kl["kev_cves"],
                     json.loads(f.read_text()).get("window")))
    if not rows:
        print("No pulls in data/history yet; run scripts/build_site.py after a pull.")
        return

    print(f"{'pull':<12}{'readiness':>14}{'KEV goal':>14}")
    for d, r, rn, g, gn, _ in rows:
        print(f"{d:<12}{f'{r} of {rn}':>14}{f'{g} of {gn}':>14}")

    def share_range(pairs):
        shares = [100 * x / n for x, n in pairs if n]
        return f"{min(shares):.0f}% to {max(shares):.0f}%" if shares else "n/a"

    print(f"\n{len(rows)} pull(s). Readiness {share_range([(r[1], r[2]) for r in rows])}; "
          f"KEV goal {share_range([(r[3], r[4]) for r in rows])}.")
    if len(rows) < 4:
        print("Fewer than four pulls: too few to call either figure stable.")

    # Overlap: weekly 30-day windows share most of their days, so they are not independent samples.
    span = lambda w: (date.fromisoformat(w[0]), date.fromisoformat(w[1]))
    for a, b in zip(rows, rows[1:]):
        if a[5] and b[5]:
            (a0, a1), (b0, b1) = span(a[5]), span(b[5])
            shared = max(0, (min(a1, b1) - max(a0, b0)).days + 1)
            print(f"{a[0]} vs {b[0]}: windows share {shared} of {(b1 - b0).days + 1} days")
    independent, last_end = [], None
    for r in rows:
        if r[5] and (last_end is None or span(r[5])[0] > last_end):
            independent.append(r)
            last_end = span(r[5])[1]
    print(f"Non-overlapping windows: {len(independent)} ({', '.join(r[0] for r in independent)}). "
          f"Readiness {share_range([(r[1], r[2]) for r in independent])}; "
          f"KEV goal {share_range([(r[3], r[4]) for r in independent])}.")
    if len(independent) < 2:
        print("Only one non-overlapping window so far: no independent check of stability yet.")

    cum = HISTORY / "kev_cumulative.json"
    if cum.exists():
        u = json.loads(cum.read_text())
        n = u["union"]
        print(f"Union of all pulls ({len(u['pulls'])} pull(s), {n['kev_cves']} KEV CVEs): readiness "
              f"{n['triage_cpe_before_kev']} of {n['triage_public_before_kev']}; KEV goal "
              f"{n['within_one_business_day']} of {n['with_cpe_now']} with CPE "
              f"({len(n['still_without_cpe'])} still without).")


if __name__ == "__main__":
    main()
