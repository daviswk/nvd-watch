# NVD Watch

A public scorecard for the U.S. vulnerability warning system (NIST NVD + CISA KEV), with a 3-page policy brief and an AI collaboration log. Class project for Intro to Tech Policy, Pardee RAND.

## Start here
1. Read `CLAUDE.md` (Claude Code reads it automatically every session).
2. Open `docs/learning/primer.html` in a browser for the full who/what/why.
3. Run the first data pull:
   ```bash
   python3 -m venv .venv && source .venv/bin/activate
   pip install -r requirements.txt
   export NVD_API_KEY=...        # optional but much faster: https://nvd.nist.gov/developers/request-an-api-key
   python scripts/fetch_sample.py --days 30
   ```
   Output goes to `data/raw/` and `data/processed/`. Put `NVD_API_KEY=...` in a `.env` file at the project root instead of exporting it if you prefer; the script reads it. Re-run on the saved raw file without hitting the NVD API with `--from-raw`.
4. Render the page:
   ```bash
   python scripts/build_site.py
   ```
   This fills `site/template.html` from `data/processed/summary.json` and writes `site/index.html`. Open it with any static server, for example `python -m http.server 8765 --directory site`.

## Layout
```
CLAUDE.md                  project context and rules for Claude Code
docs/project-plan.md       question, recommendations, roadmap
docs/brief-outline.md      3-page brief skeleton
docs/ai-collaboration-log.md
docs/sources.md
docs/research/             evidence review + raw research notes
docs/learning/             primer, reading drills, video list
design/mockups/            earlier scorecard mockups (reference only)
scripts/fetch_sample.py    NVD + KEV + EPSS sample pull
scripts/build_site.py      renders site/index.html from data/processed/summary.json
data/                      raw and processed data (git-ignored raw)
site/                      the scorecard page: template.html (source), index.html (rendered), styles.css, app.js
docs/data-notes.md         what each data pull showed and how it was checked
PRODUCT.md, DESIGN.md      product truth and the visual system (Impeccable)
```

## A first prompt for Claude Code
> Read CLAUDE.md and docs/project-plan.md. Run scripts/fetch_sample.py for the last 30 days, fix anything that breaks, then summarize CPE coverage, NIST-CVSS coverage, and status counts from data/processed/summary.json. Explain your reasoning and log any AI mistakes in docs/ai-collaboration-log.md.
