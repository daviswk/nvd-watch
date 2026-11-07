---
version: 1
slug: "site-index-html"
primary_target: "site/index.html"
related_targets: []
---

# Scorecard page — surface brief

Surface: `site/index.html`, the single NVD Watch scorecard page. Status: shaped 2026-11-07, direction chosen by Will; built the same day; finish review disposition ship on the scored fix set (six fixes plus one regression resolved).

## 1. Job and audience

Policy staff at Congress, NIST, and CISA, arriving with about two minutes, usually from the three-page brief, a colleague's link, or a search for NVD enrichment numbers, sometimes reading a printout. Visitor mode: **Persuade**. They should leave able to cite the gap, the re-check rule, and its cost in an oversight letter or an RFI 7(e) response.

## 2. Outcome and proof

Primary action: **Copy citation** (a formatted citation with the figure, the pull date, and the row's permalink). Secondary: download the brief (PDF, not yet produced; link to the outline until it exists).

Proof is ours: coverage computed weekly from the NVD API 2.0 joined to CISA KEV and FIRST EPSS, with the definition and source beside every figure. First pull (Nov 7, 2026, 30 days): 17,070 non-rejected CVEs, CPE on 22.6%, 17 of 18 KEV CVEs with CPE, NIST-sourced CVSS on 2.7%. Vendor figures appear only as attributed context. Wording rule: the gap is standardized, scanner-matchable CPE; 94% of CVEs already carry free-text CNA product names, so never say "no product data".

## 3. Selected direction

**World: the GAO Highlights page**, chosen by Will from hand 1 (Impeccable's pick; seed reference seed:c4de49fc9d16610e). Visual authority: none incumbent; this is a new world and DESIGN.md is written at finish from the build.

Structural thesis: the page is a highlights page followed by the report body. A single identity band across the top (title, week, actions), then a two-column highlights grid: left "Why this matters" in three short paragraphs; right "What we found" led by the 22.6% figure at display scale with its definition, then two findings (KEV is the gate; the fix costs less than the redirectable re-scoring effort), then "What we recommend" as a three-row table addressed to NIST, CISA, Congress. Below the highlights, the four sections run as the report body with numbered run-in headings: 1 The gap, 2 The gate, 3 The fix and its cost, 4 Who should act, ending with frozen metric definitions and a sources list.

Focal moment: the first finding. One number, its definition, and its source, in the first viewport, readable before anything else.

Signature interaction: the re-check cost box in section 3. Low, mid, and high columns driven by three minutes-per-CVE options (20/45/60, labeled as an assumption) and a CVEs-per-month input (default carried as an assumption until a backlog-based estimate exists), with the OIG offset as a fixed comparison line. Changing an input updates the columns in place and rewrites one sentence of plain text that states the result.

Material register: white report stock, one deep identity colour for the band, rules, and finding numbers, dark body text, hairline rules, a serif body with a sans for labels and tables. Faces are chosen in the build and must not come from the overused list. Not GAO's seal, name, or exact blue: the system is the highlights-page grammar, not GAO's identity, and the page says plainly who wrote it.

Implementation consequence: one static HTML page with one stylesheet and a small script for the simulator and copy-citation. Numbers are rendered into the HTML at build time by a Python step from `data/processed/summary.json`, so the page is correct with JavaScript off and prints as a report. A print stylesheet drops the band to black and keeps each section on its own page.

## 4. Scope and boundaries

Fidelity: production page, all four sections, working simulator, responsive, printable, WCAG 2.1 AA. Named target: `site/index.html` plus `site/styles.css`, `site/app.js`, and a `scripts/build_site.py` render step.

Untouched: the data pipeline's outputs and schema, docs, PRODUCT.md settled positions. Anti-goals: KPI-tile dashboard, alarm colours, charts without a text alternative, unlabeled illustrative numbers, any item on the cut list (hero map, funnel, lifecycle tracker, S7 case, CNA-vs-NIST view).

## 5. States and ranges

- CVEs per 30 days: 10,000–25,000. CPE share: 0–100%, expect 15–35%. KEV CVEs in window: 5–40. CVEs without CPE at EPSS ≥ 0.10: 0–50.
- Fresh data (pull within 10 days): normal. Stale (older): a one-line notice under the band with the pull date. Missing `summary.json`: build fails loudly; the page never ships placeholders.
- Simulator: default, user-changed, and reset; keyboard operable; values announced via a live region.
- Copy citation: idle, copied (two-second confirmation), clipboard unavailable (select-all fallback).
- Print: band flattened, simulator shows its current values as static text, definitions and sources included.

## 6. Interaction and layout

Hierarchy: band, highlights grid, four numbered sections, definitions, sources. Topology: one long page; a slim section index under the band on desktop, wrapping to show all six items on mobile; every section and metric row has an id for permalinks. Responsive: two-column highlights above 900px, single column below; tables become stacked rows under 600px. Affordances: links underlined in body text; buttons as filled or outlined rectangles in the identity colour; the simulator uses native inputs styled in the same rules. Feedback: in-place updates, no page jumps. Motion: none beyond the copy confirmation and simulator value transitions; respect reduced-motion.

## 7. Constraints and open decisions

Constraints: no dark scheme (white report stock for every reader; finish review 2026-11-07); the identity colour is the only coloured ink, the focus hue is for focus rings only; the canonical URL for the static citation comes from SITE_URL in .env once deployed; static hosting on GitHub Pages; no external font hosts if fonts are self-hosted; WCAG 2.1 AA; the five metric definitions are frozen text and must match the brief.

Open decisions a builder must not invent:
- Typeface pair (chosen in the build, documented in DESIGN.md).
- Whether the brief PDF link ships now or after the brief is written.
- The default CVEs-per-month figure in the simulator (currently an assumption; see `docs/data-notes.md`).
- Whether the KEV lag trend in section 2 uses Barracuda's annual medians (attributed) until our own multi-year KEV lag pull exists.

## Direction contract

THESIS: The scorecard is a highlights page over a report body: one finding leads, its definition and source beside it, recommendations addressed by name. It refuses the KPI-tile dashboard and the dark cyber console.

OWN-WORLD: White report stock. One identity colour, a deep teal ink, owns the band, the finding numerals, rules, and buttons; body text near-black; hairlines in warm grey. Public Sans for labels, tables, and the band; Source Serif 4 for body and finding text. Filled or outlined rectangular buttons, no radius. Run-in numbered section headings. Tables with a 2px head rule and hairline rows.

STORY: A staffer sees that most new CVEs lack scanner-matchable CPE, understands that KEV is the gate and that it arrives later every year, sees the fix costs less than redirectable effort, and copies a citation with a permalink.

FIRST VIEWPORT: Band across the top: title, week ending, Copy citation (filled) and Download the brief (outlined) at right. Under it a slim section index. Then the highlights grid: left column 400px "Why this matters", three short paragraphs; right column "What we found" led by 22.6% at 72px serif in teal with its definition at 20px, two findings below as ruled rows, then "What we recommend" as a three-row table. Section 1 begins below the fold.

FORM: GAO Highlights page, candidate 1 of 7 on the grounded list (Impeccable's pick, chosen by Will). seed:c4de49fc9d16610e

FINISH: unreviewed and undocumented is unfinished; this build ends with the finish review, the verdict, DESIGN.md, and every shipping raster carrying its provenance
