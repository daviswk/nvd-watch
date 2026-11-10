# NVD Watch

A public scorecard for the U.S. vulnerability warning system (NIST NVD + CISA KEV), with a 3-page policy brief and an AI collaboration log. Class project for Intro to Tech Policy, Pardee RAND.

## Start here
1. Read `CLAUDE.md` (Claude Code reads it automatically every session).
2. Read `docs/handoff.md` for the current state, and see the live page: https://daviswk.github.io/nvd-watch/
3. Run a data pull (the weekly GitHub Action runs the same four steps every Monday):
   ```bash
   python3 -m venv .venv && source .venv/bin/activate
   pip install -r requirements.txt
   export NVD_API_KEY=...        # optional but much faster: https://nvd.nist.gov/developers/request-an-api-key
   python scripts/fetch_sample.py --days 30   # NVD + KEV + EPSS for the last 30 days
   python scripts/kev_enrichment.py           # when each KEV CVE first got CPE (NVD change history)
   python scripts/kev_lag.py                  # median CVE-to-KEV lag by year
   ```
   Output goes to `data/raw/` and `data/processed/`. Put `NVD_API_KEY=...` in a `.env` file at the project root instead of exporting it if you prefer; the scripts read it. Re-run on the saved raw file without hitting the NVD API with `fetch_sample.py --from-raw`.
4. Render the page:
   ```bash
   python scripts/build_site.py
   ```
   This fills `site/template.html` from the files in `data/processed/` and writes `site/index.html`. It stops if the KEV file is from a different pull than `summary.json`. A fresh clone can skip step 3: the committed data builds the current page. Open it with any static server, for example `python -m http.server 8765 --directory site`.

## Layout
```
CLAUDE.md                  project context and rules for Claude Code
docs/handoff.md            current state, how to run everything, what is next
docs/project-plan.md       question, recommendations, roadmap
docs/brief-outline.md      3-page brief skeleton
docs/ai-collaboration-log.md
docs/sources.md
docs/research/             evidence review + raw research notes
design/mockups/            earlier scorecard mockups (reference only)
scripts/fetch_sample.py    NVD + KEV + EPSS pull for a 30-day window
scripts/kev_enrichment.py  CPE timing for KEV-listed CVEs (readiness, one-business-day goal)
scripts/kev_lag.py         median CVE-to-KEV lag by year
scripts/build_site.py      renders site/index.html from data/processed/
scripts/check_*.py         offline checks: KEV rules and sentences, cost model
scripts/research/          one-time measurements behind the brief (re-check volume, trigger recall)
.github/workflows/         weekly rebuild (Mondays) and Pages deploy
data/                      raw (git-ignored), processed, and one folder per pull in history/
site/                      the scorecard page: template.html (source), index.html (rendered), styles.css, app.js
docs/data-notes.md         what each data pull showed and how it was checked
PRODUCT.md, DESIGN.md      product truth and the visual system (Impeccable)
```

## A first prompt for Claude Code
> Read docs/handoff.md, CLAUDE.md and the Current conclusions list in docs/data-notes.md. Run `git pull`, then scripts/stability.py, and tell me what changed since the last pull. Explain your reasoning and log any AI mistakes in docs/ai-collaboration-log.md.
