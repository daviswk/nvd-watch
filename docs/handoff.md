# Operating manual for the next session

Written Nov 7, 2026 at the end of the first Claude Code session (Claude Fable 5.1). Read this, then `CLAUDE.md`, then the **Current conclusions** list at the top of `docs/data-notes.md`. That file is appended in order, so a section further down can revise an earlier one; the list at the top is the current state, and older passages that were revised are marked **Superseded**. Everything below is verified against the repo and the live site as of that date.

**Updated Nov 8, 2026 (Claude Opus 5.5 session):** the weekly rebuild workflow was added and its first run (manual, Nov 8 05:21 UTC) passed end to end. The page now refreshes itself every Monday, so the live numbers move week to week. See §5 item 2 and the new gotchas in §6.

**Updated Nov 8, 2026, overnight (Claude Opus 5.5, red-team round 6, branch `redteam-nov7`, not yet merged):**

- **State.** The weekly rebuild has run once: manually, Nov 8. NVD pull at 05:21 UTC, KEV history at 05:23 UTC; bot commit `b80cd47`. Its first scheduled run is Monday, Nov 9, 12:47 UTC.
- **New research.** Pre-triage readiness baseline, status-before-listing of the 13, trigger recall and volume, benefit estimate, request channel, automated mapping and scanner matching. Results are in `docs/red-team-nov7-response.md`. Scripts are in `scripts/research/`, outputs in `data/processed/`.
- **Pipeline changes (run weekly once merged):**
  - `kev_enrichment.py` also writes `data/history/kev_cumulative.json`.
  - `stability.py` reports window overlap.
  - The page shows the KEV goal as "x of y resolved, z pending" and cites OSV only while the orphan row shows.
- **Known limitation, not yet fixed in `kev_enrichment.py`.** CVEs that NIST analysed before its change history logged details have no "CPE Configuration" event for their original CPE. The rule then dates their first CPE to a later re-analysis. It does not affect the current 10 of 23, which are all 2026 CVEs. See the response doc.
- **Large inputs.** Downloaded to `data/raw/ext/` (git-ignored, ~1.4 GB): NVD yearly feeds, the CPE dictionary, EPSS files and cvelistV5.

## 1. Where the project stands

**Live:** https://daviswk.github.io/nvd-watch/ (GitHub Pages, deployed on every push to `main` by `.github/workflows/pages.yml`, and every Monday 12:47 UTC by `.github/workflows/rebuild.yml`, which pulls fresh data, commits it as github-actions[bot] and deploys). Latest pull: Nov 8, 2026 (window Oct 9 – Nov 8). Repo: https://github.com/daviswk/nvd-watch, public. Check `git log` for the latest commit; the tree is kept clean between sessions.

**The three graded deliverables**

| Deliverable | State | What remains |
|---|---|---|
| Artifact (scorecard page) | Built, reviewed (Impeccable finish review: ship), live | Nothing required. Done: weekly rebuild (`.github/workflows/rebuild.yml`, first run Nov 8), multi-year KEV lag (`scripts/kev_lag.py`), backlog-based re-check volume (`recheck_measured.json`), orphan count (`osv_orphans.json`), legacy share |
| Policy brief (≤3 pages) | Outline only: `docs/brief-outline.md` | Write it. Numbers must match the page. Export to PDF, put it in `site/` or `docs/`, and point the band's "Policy brief" button at it (currently links to the outline on GitHub) |
| AI collaboration log | `docs/ai-collaboration-log.md`, current through deploy | Keep adding a row per session. Final pass: every entry has a verification note |

## 2. How to run everything

```bash
# Windows: use the venv's python directly; no activation needed
./.venv/Scripts/python.exe scripts/fetch_sample.py --days 30     # full pull (~3 min with API key)
./.venv/Scripts/python.exe scripts/fetch_sample.py --from-raw    # reprocess data/raw/nvd_sample.json without hitting the NVD API
./.venv/Scripts/python.exe scripts/kev_enrichment.py            # NVD change history for every CVE added to KEV in the window (~70 calls); required by the build
./.venv/Scripts/python.exe scripts/build_site.py                 # renders site/index.html from site/template.html + summary.json
./.venv/Scripts/python.exe -m http.server 8765 --directory site  # local preview (or preview_start name "site" via .claude/launch.json)
```

- `.env` at the project root holds `NVD_API_KEY=...` and `SITE_URL=https://daviswk.github.io/nvd-watch/`. Both scripts read it. **Never print it; never append to it with `>>` (see §6).**
- **Edit `site/template.html`, never `site/index.html`.** The build overwrites index.html. `{{tokens}}` are filled by `build_site.py`; the build exits if a token has no value, so the page never ships a placeholder.
- After any change to the template, CSS, or JS: rebuild, then `git add site/ && git commit && git push`. Pages redeploys in about a minute; check at https://github.com/daviswk/nvd-watch/actions.
- No `gh` CLI on this machine. Read Actions status through the public API: `https://api.github.com/repos/daviswk/nvd-watch/actions/runs`.

## 3. What is settled (do not reopen without a reason)

Beyond the settled decisions in `CLAUDE.md`:

- **Visual direction:** the "GAO Highlights page" world, chosen by Will from a two-hand Impeccable direction round. White report stock, one teal ink (`#1d4e5f`), Source Serif 4 + Public Sans, no dark scheme, no cards, no kickers. Recorded in `DESIGN.md`, `.impeccable/design.json`, and the direction contract in `.impeccable/surfaces/site-index-html.md`. Not GAO's seal, name, or exact blue.
- **Mode:** Persuade. Primary reader: congressional/NIST/CISA policy staff with two minutes. Primary action: Copy citation. WCAG 2.1 AA, printable.
- **The gap is standardized CPE, never "no product data."** 94% of CVEs already carry free-text CNA product names (`affected` field). Say "scanner-matchable product data (CPE)".
- **Re-check volume is measured, not assumed (revised Nov 7).** From the whole NVD stock (`scripts/research/recheck_volume.py` -> `data/processed/recheck_measured.json`): 76,217 CVEs without CPE in Not Scheduled, Awaiting or Received, none in KEV; a one-time load of 303 already at EPSS >= 0.10 ($12K–$36K once), then 11–28 re-queues a month (simulator default 28 -> ~$30K a year at 45 minutes, 0.6% of NIST's ~5,000/month peak; ~$5K–$40K a year across the month range and 20–60 minutes). The OIG's ~$400K a year is a scale comparison, not spare money. **Retired:** the Floodline-based 16–46 a month ($8K–$66K) and everything before it (250–470, $270K–$510K); Floodline now supplies only the section 2 score-maturation figures. See `data-notes.md` Current conclusions.
- **Related tools:** link to RogoLabs (CVE.ICU, Floodline, CNA Scorecard, CNAPulse, SADP Tracker); don't duplicate them. Positioning line is in `CLAUDE.md`.
- **Status names:** API `Deferred` = display "Not Scheduled"; `Awaiting Analysis` = "Awaiting Enrichment"; `Analyzed` = "Enriched". Display names on the page, API values in code.

## 4. Where things are

| Path | What |
|---|---|
| `scripts/fetch_sample.py` | Pipeline: NVD + KEV + EPSS + Floodline → `data/processed/summary.json` and `cves_sample.csv`. Retries with backoff. |
| `scripts/build_site.py` | Render step. Draws the KEV-lag chart from `kev_lag.json`, renders the simulator defaults through `cost_model.py` (so the page is right with JS off), the stacked-table `data-label`s, the citation permalink from `SITE_URL`. |
| `scripts/cost_model.py`, `site/cost.js`, `scripts/check_cost_model.py` | The re-check cost rule: Python owns constants and wording; `cost.js` repeats the arithmetic in the browser; the check runs both (Node) and compares. |
| `site/template.html`, `styles.css`, `app.js` | The page. `app.js` is progressive enhancement only (simulator wiring, copy citation). |
| `data/processed/summary.json` | The one source of every number on the page. Committed. The CSV and raw file are git-ignored. |
| `docs/data-notes.md` | What each pull showed, caveats, the Floodline derivation, the status mapping. Append a section per pull. **When a new section changes an earlier conclusion, mark the earlier passage Superseded in place, with a pointer, and update the Current conclusions list at the top in the same edit.** |
| `docs/ai-collaboration-log.md` | Log. Add a row under "Entries from Claude Code" for each session. |
| `PRODUCT.md`, `DESIGN.md`, `.impeccable/` | Impeccable product truth, design system, surface brief with direction contract, decision-round fixtures. |
| `.github/workflows/pages.yml` | Deploys `site/` on push to `main`. |
| `.github/workflows/rebuild.yml` | Weekly rebuild: Mondays 12:47 UTC + manual (Actions → Weekly rebuild → Run workflow). fetch → kev_enrichment → kev_lag → build → commit if changed → deploy Pages. Uses the `NVD_API_KEY` repo secret. |
| `data/history/YYYY-MM-DD/`, `scripts/stability.py` | One folder per pull (written by the build). `stability.py` prints readiness and the KEV goal per pull with min/max; after 4+ pulls it says whether to cite a point or a range. |
| `.claude/launch.json` | `preview_start` config for the local server. |

## 5. What to do next, in order

1. **Write the brief** from `docs/brief-outline.md`. Three pages. Every number must match `site/index.html` **as of a named pull date** (the page now changes weekly: write "as of Nov N" and take every figure from that pull's `summary.json` and `kev_enrichment.json` in `data/history/YYYY-MM-DD/`, not from memory or from older sections of `data-notes.md`). Cost box uses the measured figures (303 once, 11–28 a month; `recheck_measured.json`). Export PDF; link it from the band button in `site/template.html`; rebuild; push.
2. ~~Weekly rebuild action~~: done. First run Nov 8 (manual): all steps passed; bot commit `b80cd47`; live page identical to the committed build. Window moved Oct 8 – Nov 7 → Oct 9 – Nov 8: coverage 22.6% → 22.3% (3,795 of 17,035); KEV cohort 35 → 30 (the 5 dropped were all listed Oct 8, old CVEs with pre-triage CPE); readiness unchanged at 10 of 23; KEV goal 29 of 30 (1 pending). The section 1 orphan row dropped off as designed. Not run weekly: `osv_orphans.py`, `recheck_volume.py`, `check_cost_model.py`. After each Monday run, `git pull` before working locally, and run `scripts/stability.py`.
3. ~~Multi-year KEV lag~~: done. `scripts/kev_lag.py` → `kev_lag.json`; the section 2 chart shows our 4 → 7 → 10 → 9, with Barracuda cited for comparison.
4. ~~Backlog-based re-check estimate~~: done (`recheck_measured.json`, on the page). Still unmeasured: whether EPSS (v5, not v4) ranks unenriched CVEs worse; keep it flagged.
5. **Final AI log pass:** every row has a verification note; add a closing "models used" line naming Claude Fable 5.1 (Nov 7) and Claude Opus (later sessions).

Things to leave alone: the detector findings on `.impeccable/decision/*.html` (spent decision fixtures; ignore-file needs Will's say-so, or delete them); two dead CSS rules (`.copied`, print `.bars .fill`) noted by the documenter.

## 6. Gotchas that cost time today

- **`.env` has no trailing newline guarantee.** Appending with `printf >>` glued `SITE_URL=` onto the API-key line and corrupted the key. Edit `.env` with a script that rewrites whole lines and prints only key names and value lengths. Never `cat` it; the harness blocks credential display anyway.
- **FIRST's EPSS API returns 504s under load.** `get_with_retry()` handles it now (5 attempts, exponential backoff). If a pull dies anyway, `--from-raw` reprocesses without refetching NVD.
- **Impeccable launcher from Git Bash:** `./.claude/skills/impeccable/scripts/impeccable.cmd <verb>` works for most verbs, but `hooks ignore-value` fails because of the space in the project path. Run that one from PowerShell: `$i = "D:\NVD Scorecard Project\nvd-watch\.claude\skills\impeccable\scripts\impeccable.cmd"; & $i hooks ignore-value <rule> "<value>" --file <path> --reason "..."`.
- **Design detector false positives:** it reads CSS `clamp()` as its max times something (reported the h1 as 168px; real 38px) and, when tokens were split across light/dark media blocks, cross-combined them into bogus contrast failures. Fixed by using single-value tokens. The `oversized-h1` ignores are already recorded for `site/index.html` and `site/template.html`.
- **Playwright viewport resets after `browser_navigate`.** Resize to 1440×900 (or 390×844) *after* navigating, before capturing. Captures taken without this came out at 2560 wide.
- **The in-app browser renders `file://` pages as static snapshots** (no CSS). Use the HTTP server via `preview_start` name `site`.
- **GitHub Pages:** the first deploy failed because the Pages site didn't exist; Will enabled it under Settings → Pages → Source: GitHub Actions, and `configure-pages` has `enablement: true`. An empty commit does not trigger the workflow unless it has no `paths` filter (it has none now).
- **Windows line endings:** git warns "LF will be replaced by CRLF" on every commit. Harmless; ignore it or set `git config core.autocrlf false` if it bothers you.
- **PHP2Shell has no CVE ID on the page on purpose.** A draft wrongly attached CVE-2026-104935 (that's the Ivanti CVE from the mockups). Only add an ID after verifying it in the NVD.

- **Pull before you work.** The Monday bot commit lands on `main`; a local session that hasn't pulled will hit a rejected push. `git pull --ff-only origin main` first.
- **Push declined for email privacy (Nov 8).** GitHub refused a push because the commit email was Will's private Gmail; Will turned off "Block command line pushes that expose my email" (Settings → Emails). If it comes back, use `8902489+daviswk@users.noreply.github.com` as this repo's `user.email`.
- **Local builds need a fresh fetch after a Monday run.** The bot commits `summary.json` but not the git-ignored `cves_sample.csv`, so after `git pull` the local CSV is a week old and `build_site.py` stops on its CPE cross-check. Run `fetch_sample.py --days 30` and `kev_enrichment.py` first (this commits a new pull; that's fine).
- **Shifting window, shifting small-n figures.** A few hours' move of the 30-day window drops whole KEV listing days (Nov 8: 35 → 30). Before reporting a change in a KEV figure, check which CVEs left or entered and why.

## 7. How this session verified things (keep doing this)

- Every page number traces to `summary.json`; `build_site.py` cross-checks the counted CPE total against the CSV and exits on disagreement.
- Spot-check data with a separate script before trusting a summary (status shares, KEV rows, EPSS coverage, weekly volume).
- Screenshots at 1440 and 390 via Playwright, plus print and dark emulation; exercise the simulator and copy button by script; check `document.documentElement.scrollWidth <= innerWidth` at 390.
- Run `impeccable detect --json site/index.html site/styles.css site/app.js` after UI edits; triage advisories, suppress only with a stated reason.
- For any UI change beyond a tweak, the Impeccable flow is: read the surface brief's direction contract, read `reference/craft-floor.md`, build, capture, spawn `impeccable-finish-reviewer`, act on its disposition, then `impeccable-documenter` if the system changed.
- Log every AI mistake in `docs/ai-collaboration-log.md` as it happens, with how it was caught.
