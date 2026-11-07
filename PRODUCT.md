# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Stack

Static HTML/CSS/JS in `site/`, reading processed JSON produced by a Python pipeline (requests, pandas) in `scripts/`. Hosted on GitHub Pages. Stretch goal: a scheduled GitHub Action rebuilds the data and page weekly. Confirmed by Will on 2026-11-07.

## Users

**Primary:** policy staff at Congress (Appropriations, Science, Homeland Security committees), NIST, and CISA. They arrive with two minutes, need to grasp the gap, the proposed fix, and its cost, and must be able to trace every number to a query or a cited source before they repeat it.

**Secondary (confirmed, not designed around):**
- Pardee RAND instructors grading the artifact, the policy brief, and the AI collaboration log for Intro to Tech Policy (MTP).
- Security defenders who depend on free NVD data (state/local/tribal/territorial governments and MS-ISAC, hospitals, small businesses) and cannot buy commercial enrichment.
- Press and vulnerability researchers who want a citable, weekly-updated coverage figure.

## Product Purpose

NVD Watch is a public, weekly-updated scorecard of the U.S. vulnerability warning system: the NIST National Vulnerability Database (NVD) and the CISA Known Exploited Vulnerabilities (KEV) catalog. It measures whether NVD product data (CPE) reaches defenders in time after NIST's April 15, 2026 triage, and prices a simple rule change that would close the gap.

It ships with a policy brief of at most three pages and an AI collaboration log. All three are graded deliverables; the brief and page must show the same numbers.

The policy question: does NIST's April 2026 triage leave exploited vulnerabilities without product data (CPE) when defenders need it, and would a published re-check rule plus quarterly performance metrics close that gap at a cost NIST can absorb?

Success: a staffer can state the gap, the re-check rule, and its cost range in their own words after one visit, and every figure they cite survives a source check. The page is also a working answer to NIST RFI question 7(e) (91 FR 52042, Aug 12, 2026): what metrics should track the NVD's success.

## Positioning

NVD Watch computes NVD coverage itself from the public NVD API, joined to CISA KEV and FIRST EPSS, with definitions shown on the page. Existing coverage figures come from vendors with interests (VulnCheck, Volerion, Cyber Strategy Institute, Barracuda) and conflict with each other (about 50% vs 8.4% enriched) because no official definition exists. NVD Watch is independent, free, reproducible, and prices its own recommendation against an OIG-documented offset instead of asking for new money.

Framing line: NIST prioritizes by who uses the software, or confirmed attacks. We propose re-checking the rest when attack signals rise, and publishing whether it works.

## Operating Context

- Data arrives weekly from three free sources: NVD API 2.0 (publication windows of at most 120 days, API key requested), the CISA KEV JSON feed, and the FIRST EPSS API. NIST's own metrics carry source `nvd@nist.gov`.
- The page is read alongside the three-page brief and the AI collaboration log, often in a committee or classroom setting, sometimes printed.
- The reader's mental model is the policy brief: background, challenges and opportunities, recommendations by stakeholder.
- Terminology the audience uses: CVE, CPE (product data), CVSS (severity score), KEV, EPSS, LEV (NIST CSWP 41), SSVC, CNA, "Not Scheduled" status, enrichment, re-queue, one-business-day KEV goal.

## Capabilities and Constraints

One scorecard page with four sections, in this order:
1. **The gap.** CPE coverage by priority tier and status, computed from the NVD API, with definitions shown.
2. **The gate.** CVE-to-KEV lag trend, with PHP2Shell as the worked example (probes Oct 17, unsuccessful; patch Oct 21; confirmed exploitation Oct 24–25; KEV Oct 26).
3. **The fix and its cost.** An interactive re-check rule simulator: CVEs per month, percent of NIST capacity, cost range against the OIG offset. Minutes-per-CVE is a 20/45/60 range labeled as an assumption.
4. **Who should act.** Recommendations for NIST, CISA, and Congress, plus five quarterly metrics with frozen definitions.

Settled positions future work must preserve:
- The gap is product data (CPE), not severity scores. Do not attack the "stop re-scoring" half of NIST's policy.
- KEV is the gate: for most software, CPE comes only after a KEV listing. Median CVE-to-KEV lag rose 6 → 9 → 12 → 14 days (2023–2026, Barracuda).
- EPSS is a re-check trigger, not an intake screen.
- The ask is a rule change, not new money: about 250–470 CVEs/month, roughly 5–9% of NIST's ~5,000/month ceiling, crude cost ~$270K–$510K/yr vs. the OIG's ~$400K/yr redirectable re-scoring effort.

Hard rules:
- Never invent data. Anything illustrative is labeled "illustrative" on the page. Every number traces to a query or a cited source.
- Vendor-sourced and single-source figures are attributed as such.
- Status-category definitions changed on Apr 15, 2026; the page keeps a change log.

Out of scope, cut on purpose: wildfire/hero map, funnel chart, standalone lifecycle tracker, Siemens S7 case (one sentence in the brief only), CNA-vs-NIST score disagreement view, GitLab, cve.now, formal verification, forum monitoring.

Open product facts (undecided, do not fabricate):
- Actual coverage figures await our own NVD pull; vendor numbers are placeholders until then.
- Whether EPSS v4 accuracy degrades on unenriched CVEs is unmeasured.
- No per-CVE enrichment cost exists; cost figures are crude upper bounds.

## Brand Commitments

- Name: **NVD Watch**.
- Author: Will Davis, Pardee RAND Graduate School, Intro to Tech Policy (MTP), AI-Augmented Policy Project.
- Voice: plain, concise, evidence-first. Explain the reasoning, not just the result. No hype, no alarmism; the framing line above is the register.
- Transparency is part of the identity: definitions, sources, and assumptions are visible on the page, and AI involvement is disclosed in the collaboration log.
- Earlier canvas mockups in `design/mockups/` (`Scorecard2.dc.html` closest to intent) are reference for layout, copy, and logic only, not a binding visual direction. Headline numbers in them are outdated.

## Evidence on Hand

- Research: `docs/research/evidence-review.md` and `docs/research/notes/` (gap evidence, EPSS prioritization, AI volume, stakeholders and governance).
- Sources with links: `docs/sources.md`. Primary sources preferred: NIST, Commerce OIG (OIG-26-020-I, May 26, 2026), Federal Register, FIRST, CISA.
- Plan, brief skeleton, and AI log: `docs/project-plan.md`, `docs/brief-outline.md`, `docs/ai-collaboration-log.md`.
- Starter pipeline: `scripts/fetch_sample.py` (untested against live endpoints as of 2026-11-07). Outputs land in `data/raw/` (git-ignored) and `data/processed/`.
- Learning materials and talk track: `docs/learning/primer.html`.

Absences future work must not fabricate: no processed data yet (`data/processed/` holds only `.gitkeep`), no testimonials, no endorsements, no logo, no measured per-CVE cost, no verified figures for "V-etalon", GPT-6 Cyber, or Ivanti "6–12 days".

## Product Principles

1. **Every number is traceable.** A figure appears only with its query or citation within reach; illustrative content is labeled as such.
2. **The gap is product data, not scores.** Keep the argument on CPE coverage and the KEV gate; do not relitigate re-scoring.
3. **Price the fix against what exists.** The recommendation is a rule change inside current capacity, measured against the OIG offset, never a funding ask.
4. **Measure, then publish.** The five frozen quarterly metrics are the product's lasting contribution; definitions do not drift.
5. **Simple and explained.** Prefer the simplest structure that a staffer can retell in two minutes, with the reasoning visible.

## Accessibility & Inclusion

Target WCAG 2.1 AA (the standard Section 508 points to). Keyboard-operable simulator, sufficient contrast, text alternatives for every chart, and the page should read well when printed since it shares numbers with the brief. Confirmed by Will on 2026-11-07.
