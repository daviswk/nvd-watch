# Red-team round 6 (Nov 7, 2026): overnight task spec

Will is asleep. Work through this file top to bottom without asking questions. When something is
ambiguous, take the most reasonable reading, write down which reading you took, and keep going.
Read `CLAUDE.md` and `docs/handoff.md` first; their rules still apply except where this file says otherwise.

## Ground rules

1. **Branch, not main.** Work on `redteam-nov7`. Never push to `main`, never deploy Pages, never touch
   `.github/workflows/`. Will reviews in the morning and merges.
2. **Measure, don't decide.** Run the tests, fix factual errors and stale docs, and draft proposed
   wording. Do **not** change the policy argument itself: the headline asks, the spine, the five
   metric definitions or the recommendation in `docs/brief-outline.md`. Put those changes in the
   report as proposals with the evidence behind them.
3. **No outside actions.** Do not submit anything to NIST/NVD, open issues on other repos, or email
   anyone. Do not rewrite git history or change git config.
4. **Never invent data.** Every number traces to a script you ran or a source you fetched. Label
   vendor and single-source figures. Small n gets counts, not percentages.
5. **AI log:** this round is in scope for `docs/ai-collaboration-log.md`. Add rows in the existing
   format as described under *AI collaboration log* below, and log your own mistakes as they happen,
   as `CLAUDE.md` already requires.
6. **Blocked?** Write what blocked you and what would unblock it, then move to the next task.
7. **Scripts:** new research scripts go in `scripts/research/`, outputs in `data/processed/`
   (or `data/raw/` if large; it is git-ignored). Each script gets a docstring: question, inputs,
   outputs, how to re-run.

## Tasks, in order

### Must

**M1. Pre-triage baseline.** Does readiness (CPE before KEV listing) look worse after the Apr 15, 2026
triage than before it? Run the `kev_enrichment.py` logic on CVEs added to KEV Oct 8 – Nov 7, 2025
(and, if time allows, Jan 8 – Feb 7, 2026). Same readiness rules: public before listing, compare the
first CPE change-history event with NVD's KEV event by timestamp. Report x of n for each period next
to today's 10 of 23. *Done when:* a table with three periods and the exclusions shown.

**M2. Were the 13 parked?** For the 13 KEV CVEs that lacked CPE before listing (current
`kev_enrichment.json`, listed cohort), find their NVD status the day before listing. Try a dated NVD
mirror with commit history (e.g. github.com/fkie-cad/nvd-json-data-feeds): fetch only the files for
those CVEs at the right commits; do not clone the whole repo if it is huge. *Done when:* each of the
13 has a status (Not Scheduled / Awaiting / Received / other / unknown) and the source of it.

**M3. Which trigger works?** Over all CVEs added to KEV Jan 1, 2025 – Nov 7, 2026 that had no CPE
before listing (and no pre-triage CPE), measure recall: did each trigger fire before the KEV listing?
Triggers: EPSS ≥ 0.10, 0.05, 0.01 (EPSS file dated the day before listing); CISA Vulnrichment SSVC
Exploitation = poc or active (from the ADP container in the CVE record; use its timestamp if
available, otherwise say it can't be dated); LEV if computable from EPSS history (note it is not an
independent signal). Then measure each trigger's volume on the current stock (no CPE, not KEV:
one-time load and monthly flow, as in `recheck_volume.py`). *Done when:* one table, trigger × (recall
x of n, one-time load, monthly flow, cost at 45 min and $120/h via `cost_model.py`). Mark the EPSS
model change (v4 → v5 on Jun 15, 2026) in the recall rows.

**M4. Benefit estimate.** Sum EPSS over the 303 stock CVEs at ≥ 0.10 (and over each M3 trigger's
one-time load). EPSS is a 30-day probability of exploitation *activity*, not compromise; say so.
*Done when:* expected events per 30 days, per trigger, next to its cost.

**M5. The existing request channel.** Research only: what NIST publishes about requesting enrichment
of a Not Scheduled CVE (process, address, any stated turnaround, any public data on requests).
Primary sources only. *Done when:* a short verified summary with links, and a note that a live test
(Will submitting a request for CVE-2026-59774) is his to do.

### Should

**S1. Automated mapping.** For CVEs in the current 30-day pull without CPE: (a) share whose CNA
`affected` vendor + product exactly match a CPE dictionary entry (normalize case and spaces only;
report the rule); (b) share of CNA records that already carry `affected[].cpes` (check the CVE record,
e.g. cvelistV5, since the NVD API may not pass it through). Verify the CVE Record Format has that
field before relying on it. *Done when:* both shares with n.

**S2. Who is actually blind.** From primary docs, how Grype and Trivy match vulnerabilities (NVD CPE
vs GHSA/distro feeds). For 10 random orphans from `osv_orphans.json` (re-run on the current window
only if feasible; otherwise use the Nov 7 file and say so), check whether a public scanner plugin
or WPScan entry exists. *Done when:* a short table and a one-paragraph verdict on the harm chain.

**S3. Readiness at 1 vs 7 days public.** Report both from the listed cohort (expected: 10 of 23 and
8 of 14). Add the median and max days public without CPE.

**S4. Cumulative KEV cohort.** Change `kev_enrichment.py` so each run also appends its rows to a
cumulative file keyed by CVE ID (latest row wins), and report readiness on the union. Keep the
existing outputs and the build's checks unchanged.

**S5. Honest stability.** Weekly 30-day windows overlap ~23 days. Change `stability.py` to say so and
to compare only non-overlapping windows (or report cumulative n). Don't break the existing output.

**S6. A better brief figure.** Propose (don't replace) a figure: readiness or time-to-CPE on a cohort
old enough to have filled in. A data file and a rough chart are enough.

### Doc and page fixes (apply these; they are factual, not argument)

- `CLAUDE.md` Settled decisions: lead the re-check bullet with the measured 303 once / 11–28 a month;
  mark 16–46 and $8K–$66K as retired.
- `docs/research/evidence-review.md` line ~47 ("CNA records do not supply CPE at all"): correct per S1.
- `docs/handoff.md`: the weekly rebuild has run (manual, Nov 8 05:23 UTC); update the state.
- `site/template.html`: the sources note citing "the section 1 orphan count" and the link to
  `osv_orphans.json` should appear only when the orphan row does; stop publishing a stale
  `site/data/osv_orphans.json`. While a KEV CVE is pending, word the goal as "x of y resolved,
  z pending" rather than "x of n". Rebuild with `--from-raw` only if the raw file exists; otherwise
  change the template and say the next scheduled run will render it.
- `docs/brief-outline.md`: factual fixes only. PHP2Shell: KEV listed 1–2 days after the first public
  exploitation report (the Oct 17 honeypot hit predates disclosure). 37.9%: "one snapshot", not
  [stable], and drop "they stay that way" unless M2 or another test supports it. Mark other number
  drift (34 of 35 → current) with a note to use the `brief-v1` tag.

## AI collaboration log

Add two rows to the *Entries from Claude Code* table in `docs/ai-collaboration-log.md`, matching the
columns and style of the existing Nov 7 red-team rows:

1. **The critique itself (Nov 7, evening).** Will asked Claude (Opus 5.5, claude.ai chat, with the repo
   cloned read-only) to red-team the project and outline without extrapolating to the unwritten brief,
   then to scope answers and list "leaks". It produced 19 pushback points, a scope plan, and leak
   lists; Will then added the weekly rebuild workflow (drafted in that chat), turned on GitHub's
   private-email setting, and the critique was redone against the first live pull. This task file is
   that chat's output. Under "where the AI failed or couldn't verify", list the chat's claims that
   were unverified when made and that this session tested: the CVE Record Format `affected[].cpes`
   field, the fkie-cad mirror carrying `vulnStatus`, the 1-vs-7-day readiness recount, and anything
   from points 1–19 that your results contradict.
2. **This overnight session.** What you ran, what changed, what failed or was wrong (yours or the
   chat's), and how each result was verified.

## The morning report

Write `docs/red-team-nov7-response.md`:

1. **Top 5 results** in plain language, each in two sentences.
2. **Decisions for Will**, each with the evidence and your recommendation:
   - Does the EPSS-only headline ask survive M3? Propose a stopping rule (recall at least X% at under
     Y re-queues a month) with values justified by the M3 table, and say what the headline ask should
     become if it fails.
   - Does M1 support "the April triage caused the gap", or should the framing become "the gap persists"?
   - Does M2 support the side-door story, or is it a queue-speed story?
   - Should automated mapping (S1) be added as an alternative, or replace the CISA ask?
   - Metric set: add readiness? drop or merge metric 5?
3. **Pushback status table**: each of points 1–19 below → addressed / partly / not, with the file or
   number that settles it.
4. **What you changed**, with commit hashes; **what you got wrong** along the way; **what's still open.**
5. A pointer to the two new AI-log rows.

Open a pull request from `redteam-nov7` to `main` with the report as the description summary.

## The pushback being answered (points 1–19)

1. Headline EPSS trigger caught 1 of 13 harm cases; better triggers are demoted to sub-asks; LEV derives from EPSS.
2. Cost priced on the 0.10 rule; benefit implied for broader triggers.
3. No benefit estimate.
4. NIST's Not Scheduled definition already allows requests ("side door" exists).
5. Missing alternative: automated CNA-to-CPE mapping; `has_cpe` ignores CNA-supplied CPE.
6. No pre-triage baseline for a question about the April triage.
7. Findings 1 and 2 not shown to be the same CVEs (status before listing unknown).
8. Readiness is sensitive to the public-days cutoff; harm is measured in days and never stated.
9. Scanner dependence rests on one translated blog post; possible mismatch between CPE-dependent tools and orphan software.
10. The brief's figure (0% CPE in Not Scheduled) is true by definition; 22% is a young, still-filling window.
11. "They stay that way" rests on one snapshot.
12. PHP2Shell undercuts "KEV is late"; lag fell in 2026; KEV narrow by design (BOD 22-01).
13. AI "why now" contradicts its own sources; FIRST's flat actionable burden supports NIST's triage; two Anthropic/Claude COI citations.
14. Readiness is not among the five metrics; metric 1 by NVD status is definitional; metric 3 already met; metric 5 is a log.
15. Liveness shows outsiders can compute metrics 1–3, weakening "NIST must publish them".
16. NIST ask is four asks; Congress ask has no live vehicle; RFI comments closed Oct 13.
17. EPSS threshold unstable across model versions; flow fell 28 → 12 while volume rose; displacement cost unstated.
18. Weekly 30-day windows overlap, so stability ranges look narrower than they are.
19. Readiness n doesn't grow because each run rebuilds its cohort from the current window.
