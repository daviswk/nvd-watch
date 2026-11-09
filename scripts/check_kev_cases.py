"""
check_kev_cases.py — do the KEV rules and the KEV sentences hold in every case a Monday pull can produce?

The live window shows only some cases (today: every listed CVE met the goal, one is pending). This runs
the same code on a small fixture that has the others: a CVE with CPE but no KEV event in the NVD history,
a pending CVE that was public before its listing, a pending CVE that is past the goal, and a late CPE.

No network. Tests kev_enrichment.judge() and stats(), and build_site.kev_tokens().

Run after a change to scripts/kev_enrichment.py or to the KEV wording in scripts/build_site.py:
  python scripts/check_kev_cases.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from build_site import kev_tokens  # noqa: E402
from kev_enrichment import judge, stats  # noqa: E402

TODAY = "2026-11-09"   # a Monday; the pull date for every fixture row
NIST = "nvd@nist.gov"


def case(cve_id, published, kev_day, cpe_time=None, kev_time=None, cpe_source=NIST):
    return judge(cve_id=cve_id, kev_day=kev_day, pub_day=published, status="Analyzed" if cpe_time else "Undergoing Analysis",
                 cpe_time=cpe_time, cpe_source=cpe_source if cpe_time else None, kev_time=kev_time,
                 n_events=3, in_sample=False, today=TODAY)


# The cases in the Nov 9, 2026 window.
READY = case("CVE-A", "2026-10-20", "2026-10-27", "2026-10-21T15:00:00.000", "2026-10-27T19:00:00.000")
AFTER_FAST = case("CVE-B", "2026-10-13", "2026-10-23", "2026-10-23T22:40:00.000", "2026-10-23T22:00:00.000")
# Listed Friday, CPE Monday: one business day (the CVE-2026-110447 pattern, checked by hand in data-notes.md).
AFTER_MONDAY = case("CVE-C", "2026-10-13", "2026-10-23", "2026-10-26T16:48:00.000", "2026-10-23T22:00:00.000")
LISTED_BEFORE_PUBLICATION = case("CVE-D", "2026-11-03", "2026-10-30", "2026-11-03T18:00:00.000", "2026-10-30T19:00:00.000")
PRE_TRIAGE = case("CVE-E", "2021-05-01", "2026-10-15", "2021-05-10T12:00:00.000", "2026-10-15T19:00:00.000")
PENDING = case("CVE-F", "2026-11-06", "2026-11-06", kev_time="2026-11-06T23:00:00.000")   # listed Friday, pull Monday
BASE = [READY, AFTER_FAST, AFTER_MONDAY, LISTED_BEFORE_PUBLICATION, PRE_TRIAGE, PENDING]

# The cases the window does not show today.
NO_KEV_EVENT = case("CVE-G", "2026-10-13", "2026-10-28", "2026-10-29T10:00:00.000")       # NVD logged no KEV event
PENDING_PUBLIC = case("CVE-H", "2026-11-04", "2026-11-06", kev_time="2026-11-06T23:00:00.000")
OVERDUE = case("CVE-I", "2026-10-20", "2026-11-02", kev_time="2026-11-02T19:00:00.000")  # listed Monday, a week ago
LATE = case("CVE-J", "2026-10-13", "2026-10-19", "2026-10-22T15:00:00.000", "2026-10-19T19:00:00.000")
NOT_NIST = case("CVE-K", "2026-10-13", "2026-10-23", "2026-10-23T23:00:00.000", "2026-10-23T22:00:00.000", cpe_source="cna@example.org")

FAST = "Once CISA confirms an attack, NIST moves fast. Before that, it mostly waits."
MISSES = "Even after CISA confirms an attack, NIST sometimes misses its own goal."

checks = 0


def expect(name, got, want):
    global checks
    checks += 1
    if got != want:
        sys.exit(f"FAIL {name}:\n  got:  {got!r}\n  want: {want!r}")


def tokens(rows):
    return kev_tokens({"rows": rows, "listed_in_window": stats(rows)})


def main():
    # Row rules.
    expect("ready: CPE before the KEV event", READY["cpe_before_kev"], True)
    expect("Friday listing, Monday CPE: one business day", AFTER_MONDAY["business_days_kev_to_cpe"], 1)
    expect("listed before publication: not public before listing", LISTED_BEFORE_PUBLICATION["public_before_kev"], False)
    expect("listed before publication: clock starts at publication", LISTED_BEFORE_PUBLICATION["business_days_kev_to_cpe"], 0)
    expect("pre-triage CPE", PRE_TRIAGE["cpe_before_triage"], True)
    expect("pending, listed Friday, pull Monday: 1 business day gone", PENDING["business_days_without_cpe"], 1)
    expect("no KEV event: falls back to the KEV date", NO_KEV_EVENT["cpe_before_kev"], False)
    expect("overdue: 5 business days gone", OVERDUE["business_days_without_cpe"], 5)
    expect("late CPE: 3 business days", LATE["business_days_kev_to_cpe"], 3)

    # 1. Today's shape: all met, one pending.
    s, t = stats(BASE), tokens(BASE)
    expect("base: counts", (s["kev_cves"], s["with_cpe_now"], s["within_one_business_day"], s["overdue_without_cpe"]), (6, 5, 5, 0))
    expect("base: readiness", (s["triage_public_before_kev"], s["triage_cpe_before_kev"], s["triage_cpe_only_after_kev"]), (3, 1, 2))
    expect("base: within two hours", s["triage_cpe_within_2h_of_kev"], 1)
    expect("base: headline", t["ke_headline"], FAST)
    expect("base: goal", t["ke_l_goal"], "5 of 5 resolved, 1 pending")
    expect("base: goal sentence", t["ke_l_goal_sentence"], "5 of the 5 with CPE so far had it within one business day (1 still pending)")
    expect("base: after phrase", (t["ke_l_after_phrase"], t["ke_l_not_yet"]), ("The other 2", ""))
    expect("base: NIST clause", t["ke_l_nist_clause"], ", every first CPE record from NIST")
    expect("base: pending note", t["ke_pending_note"], " CVE-F (listed November 6, 2026) has no CPE yet.")

    # 2. CPE exists, NVD logged no KEV event: stats() raised TypeError before Nov 9, 2026.
    s = stats(BASE + [NO_KEV_EVENT])
    expect("no KEV event: counted as CPE only after", s["triage_cpe_only_after_kev"], 3)
    expect("no KEV event: not counted within two hours", s["triage_cpe_within_2h_of_kev"], 1)

    # 3. A pending CVE that was public before listing: the page said "The other 2" of 3 others.
    s, t = stats(BASE + [PENDING_PUBLIC]), tokens(BASE + [PENDING_PUBLIC])
    expect("pending public: denominator", s["triage_public_before_kev"], 4)
    expect("pending public: after phrase", t["ke_l_after_phrase"], "Another 2")
    expect("pending public: not-yet sentence", t["ke_l_not_yet"], " The remaining 1 has no CPE yet.")
    expect("pending public: goal", t["ke_l_goal"], "5 of 5 resolved, 2 pending")
    expect("pending public: headline", t["ke_headline"], FAST)

    # 4. A pending CVE past the goal: it stayed "pending" and the page said NIST meets its goal.
    s, t = stats(BASE + [OVERDUE]), tokens(BASE + [OVERDUE])
    expect("overdue: count", s["overdue_without_cpe"], 1)
    expect("overdue: headline", t["ke_headline"], MISSES)
    expect("overdue: verdict", t["ke_verdict"], "1 took longer than one business day.")
    expect("overdue: goal", t["ke_l_goal"], "5 of 6 resolved, 1 pending")
    expect("overdue: goal sentence", t["ke_l_goal_sentence"],
           "5 of 7 had CPE within one business day; 1 still had none after more than one business day (1 more still pending)")

    # 5. A late CPE, nothing pending.
    rows = [READY, AFTER_FAST, AFTER_MONDAY, LISTED_BEFORE_PUBLICATION, PRE_TRIAGE, LATE]
    t = tokens(rows)
    expect("late: headline", t["ke_headline"], MISSES)
    expect("late: verdict", t["ke_verdict"], "1 took longer than one business day.")
    expect("late: goal", t["ke_l_goal"], "5 of 6")
    expect("late: goal sentence", t["ke_l_goal_sentence"], "5 of 6 had CPE within one business day")

    # 6. A first CPE record that NIST did not add.
    t = tokens(BASE + [NOT_NIST])
    expect("not NIST: clause", t["ke_l_nist_clause"], "; NIST added the first CPE record for 5 of the 6")

    print(f"KEV rules and sentences hold in {checks} checks.")


if __name__ == "__main__":
    main()
