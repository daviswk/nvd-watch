"""
stability.py — are the small-n KEV figures stable from one weekly pull to the next?

Reads  data/history/YYYY-MM-DD/kev_enrichment.json (written by build_site.py on every build)
Prints readiness (CPE before the KEV listing) and NIST's one-business-day goal, x of n, per pull,
then the min and max share of each.

Why: 10 of 23 and 34 of 35 come from one 30-day window. If they swing between pulls, the brief
should report a range, not a point. Weekly pulls use overlapping 30-day windows, so consecutive
weeks share most of their CVEs: treat this as a check for swings, not independent samples.

Usage:
  python scripts/stability.py
"""

import json
from pathlib import Path

HISTORY = Path(__file__).resolve().parent.parent / "data" / "history"


def main():
    rows = []
    for f in sorted(HISTORY.glob("*/kev_enrichment.json")):
        kl = json.loads(f.read_text())["listed_in_window"]
        rows.append((f.parent.name,
                     kl["triage_cpe_before_kev"], kl["triage_public_before_kev"],
                     kl["within_one_business_day"], kl["kev_cves"]))
    if not rows:
        print("No pulls in data/history yet; run scripts/build_site.py after a pull.")
        return

    print(f"{'pull':<12}{'readiness':>14}{'KEV goal':>14}")
    for d, r, rn, g, gn in rows:
        print(f"{d:<12}{f'{r} of {rn}':>14}{f'{g} of {gn}':>14}")

    def share_range(pairs):
        shares = [100 * x / n for x, n in pairs if n]
        return f"{min(shares):.0f}% to {max(shares):.0f}%" if shares else "n/a"

    print(f"\n{len(rows)} pull(s). Readiness {share_range([(r[1], r[2]) for r in rows])}; "
          f"KEV goal {share_range([(r[3], r[4]) for r in rows])}.")
    if len(rows) < 4:
        print("Fewer than four pulls: too few to call either figure stable.")


if __name__ == "__main__":
    main()
