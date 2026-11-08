"""kev_history_rows.py — one readiness row per CVE added to KEV in a date range (cached).

Question: for every CVE CISA added to KEV between two dates, when did NVD first add CPE, relative to
the moment NVD recorded the KEV listing? This is the per-CVE input for the red-team round of Nov 7,
2026 (docs/red-team-nov7.md): M1 (pre-triage baseline), M3 (trigger recall), S3 (1 vs 7 days public).

Method: exactly `row_for()` in scripts/kev_enrichment.py (NVD CVE API for publication date and status,
NVD CVE Change History API for the first "CPE Configuration" Added/Changed event and the KEV event),
so the rules match the page's readiness figure. Rows are cached; a re-run fetches only missing CVEs.

Inputs:  CISA KEV JSON (live), NVD API (reads NVD_API_KEY from .env)
Outputs: data/raw/kev_history_rows.json  {cve_id: row}  (git-ignored; ~2 NVD calls per CVE)
Re-run:  python scripts/research/kev_history_rows.py 2025-01-01 2026-11-07
"""
import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from fetch_sample import fetch_kev, load_dotenv  # noqa: E402
from kev_enrichment import row_for  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
CACHE = ROOT / "data" / "raw" / "kev_history_rows.json"


def main(start, end):
    load_dotenv()
    key = os.environ.get("NVD_API_KEY")
    headers = {"apiKey": key} if key else {}
    kev = fetch_kev()
    ids = sorted(c for c, d in kev.items() if d and start <= d <= end)
    rows = json.loads(CACHE.read_text()) if CACHE.exists() else {}
    todo = [c for c in ids if c not in rows]
    print(f"KEV adds {start}..{end}: {len(ids)}; cached {len(ids) - len(todo)}; fetching {len(todo)}")
    for i, c in enumerate(todo, 1):
        rows[c] = row_for(c, kev[c], headers, in_sample=False)
        time.sleep(0.7 if key else 6)          # NVD: 50 requests / 30 s with a key
        if i % 25 == 0:
            CACHE.write_text(json.dumps(rows, indent=1, default=int))
    CACHE.write_text(json.dumps(rows, indent=1, default=int))
    print(f"wrote {CACHE} ({len(rows)} rows)")


if __name__ == "__main__":
    main(*sys.argv[1:3])
