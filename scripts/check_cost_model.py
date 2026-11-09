"""
check_cost_model.py — do the Python and browser cost estimates print the same strings?

scripts/cost_model.py renders the estimate at build time; site/cost.js recomputes it in the
browser. Both read one model (constants and wording), but the arithmetic exists twice. This runs
site/cost.js under Node for a spread of inputs and compares every output string with Python's.

Run before pushing a change to either file (needs Node):
  python scripts/check_cost_model.py
"""

import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import cost_model as cm  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent

# (cves, minutes, rate, one_time): the page default (EPSS 0.05: 36 a month, 443 once), the 0.10 figures beside
# it, zero, the one-time load as a monthly figure, the $1M+ branch, ratio just over 1, a non-default rate,
# and an off-grid volume.
CASES = [
    (36, 45, 120, 443), (28, 45, 120, 303), (0, 45, 120, 0), (303, 20, 120, 303), (5000, 60, 120, 303),
    (500, 60, 120, 0), (445, 45, 120, 0), (28, 60, 95, 303), (1234, 20, 250, 3384), (11, 45, 120, 443),
]

JS = """
const C = require(process.argv[1]);
const model = JSON.parse(process.argv[2]);
const cases = JSON.parse(process.argv[3]);
console.log(JSON.stringify(cases.map(([c, m, r, o]) => C.outputs(model, c, m, r, o))));
"""


def main():
    try:
        out = subprocess.run(
            ["node", "-e", JS, str(ROOT / "site" / "cost.js"), json.dumps(cm.MODEL), json.dumps(CASES)],
            capture_output=True, text=True, check=True, encoding="utf-8",
        ).stdout
    except FileNotFoundError:
        sys.exit("node not found; install Node to run this check")
    js = json.loads(out)
    bad = 0
    for case, got in zip(CASES, js):
        want = cm.outputs(case[0], minutes=case[1], rate=case[2], one_time=case[3])
        for k in want:
            if want[k] != got.get(k):
                bad += 1
                print(f"MISMATCH {case} {k}:\n  python: {want[k]}\n  js:     {got.get(k)}")
    if bad:
        sys.exit(f"{bad} mismatched string(s)")
    print(f"cost.js and cost_model.py agree on {len(CASES)} cases x {len(js[0])} outputs.")


if __name__ == "__main__":
    main()
