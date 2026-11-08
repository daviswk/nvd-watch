"""
cost_model.py — the re-check cost rule, in one place.

Owns every input and every sentence of the cost estimate: NIST's peak monthly output, the OIG
re-scoring figure, the hourly rate, the minutes options, the money format, and the verdict wording.

Two implementations of the arithmetic exist on purpose: this one renders the page at build time
(correct with JavaScript off and in print), and site/cost.js updates it in the browser. cost.js
takes its constants and wording from MODEL (written into the page and site/data/cost_model.json),
so only the arithmetic is duplicated, and scripts/check_cost_model.py checks that the two agree.

Rounding is half-up everywhere (JavaScript's Math.round), not Python's round-half-even.
"""

import json
import math

CAPACITY_PER_MONTH = 5000   # OIG: NIST has never processed more than 5,000 CVEs in a month (peak output, not a ceiling)
OIG_PER_YEAR = 400_000      # OIG: ~$800K over two years from minimizing re-scoring, i.e. ~$400K a year
RATE = 120                  # loaded cost per analyst-hour, $ (assumption, shown as one)
MINUTES = (20, 45, 60)      # analyst-minutes per CVE (no published figure; three plausible values)
DEFAULT_MINUTES = 45

# Scale comparison only: NIST already stopped routine re-scoring in April 2026 and moved that
# capacity to triage, so the OIG figure is not unspent money the rule can draw on.
VERDICT = ("{share} the value of the routine re-scoring NIST stopped in April 2026 (the Commerce OIG put it at "
           "roughly {oig} a year; NIST disputes the figure). That capacity already went to triage, so this "
           "compares scale; it is not spare money")
SHARE_UNDER = "about {pct}% of"
SHARE_OVER = "about {times} times"
SENTENCE = ("Re-checking <b>{cves} CVEs a month</b> at {minutes} analyst-minutes each takes about "
            "<b>{hours} analyst-hours a year</b>, {capacity} of NIST's peak monthly output, and costs about "
            "<b>{cost} a year</b> at ${rate} an hour: {verdict}.")

MODEL = {
    "capacity_per_month": CAPACITY_PER_MONTH,
    "oig_per_year": OIG_PER_YEAR,
    "rate": RATE,
    "minutes": list(MINUTES),
    "default_minutes": DEFAULT_MINUTES,
    "verdict": VERDICT,
    "share_under": SHARE_UNDER,
    "share_over": SHARE_OVER,
    "sentence": SENTENCE,
}


def half_up(x):
    return math.floor(x + 0.5)


def num(n):
    return f"{half_up(n):,}"


def money(n):
    if n >= 1e6:
        return "$" + f"{half_up(n / 1e4) / 100:.2f}".rstrip("0").rstrip(".") + "M"
    return f"${num(n / 1000)}K"


def outputs(cves, minutes=DEFAULT_MINUTES, rate=RATE, one_time=0):
    """Every string the estimate shows, for one set of inputs. site/cost.js returns the same dict."""
    hours = cves * 12 * minutes / 60
    cost = hours * rate
    lo, hi = (cves * 12 * m / 60 * rate for m in (min(MINUTES), max(MINUTES)))
    capacity = f"{half_up(1000 * cves / CAPACITY_PER_MONTH) / 10:.1f}%"
    ratio = cost / OIG_PER_YEAR
    share = (SHARE_UNDER.format(pct=half_up(100 * ratio)) if ratio <= 1
             else SHARE_OVER.format(times=f"{half_up(ratio * 10) / 10:g}"))
    verdict = VERDICT.format(share=share, oig=money(OIG_PER_YEAR))
    return {
        "hours": num(hours),
        "capacity": capacity,
        "cost": money(cost),
        "low_high": f"{money(lo)} to {money(hi)}",
        "offset": f"{half_up(100 * ratio)}%",
        "once": money(one_time * minutes / 60 * rate),
        "sentence": SENTENCE.format(cves=num(cves), minutes=minutes, hours=num(hours), capacity=capacity,
                                    cost=money(cost), rate=num(rate), verdict=verdict),
    }


def page_json():
    """MODEL as JSON that is safe inside a <script> element (the wording contains </b>)."""
    return json.dumps(MODEL).replace("</", "<\\/")
