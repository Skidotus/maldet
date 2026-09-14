"""
Builds a stratified random sample of real findings from the DB for a
hand-labeled evaluation set — the real precision/recall check that
train_classifier.py's own weak-label test set can't provide (see NOTES.md).

Stratified by (tool, normalized severity) rather than pure random, because
Bandit alone accounts for ~93% of all findings (mostly low-severity
boilerplate) — a flat random sample would be almost entirely one tool's
noise and say little about the other four detectors. Each stratum is
capped at TARGET_PER_STRATUM (or its whole population if smaller), so rare
but important buckets (e.g. bandit's 170 "high" findings) get meaningful
coverage instead of being drowned out.

Writes eval_sample.json with one entry per sampled finding, plus empty
ai_suggested_label / ai_reason / human_label fields for the next two
scripts (label_with_ai.py, review_labels.py) to fill in.

Run standalone: `python3 build_eval_sample.py`. Refuses to run if
eval_sample.json already contains hand-review labels — pass --force to
rebuild anyway, which backs the existing file up first.
"""

import json
import os
import shutil
import sys
from datetime import datetime
import random

import pymysql

from config import DB_HOST, DB_USER, DB_PASSWORD, DB_NAME
from scanner import normalize_severity

TARGET_PER_STRATUM = 15
OUTPUT_PATH = "eval_sample.json"
SEED = 42

FORCE = "--force" in sys.argv


def guard_existing_labels(path):
    """Refuse to clobber hand-review work.

    This script writes OUTPUT_PATH unconditionally, so re-running it after
    someone has labeled the sample would silently destroy those labels —
    hours of review with no warning and no backup. The labels are the only
    ground truth this project has (evaluate_classifier.py measures against
    them), so they're far more expensive to reproduce than the sample is.
    Bail out unless the caller explicitly passes --force, and even then
    take a timestamped copy first.
    """
    if not os.path.exists(path):
        return

    try:
        with open(path) as f:
            existing = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        print(f"{path} exists but couldn't be read ({e}).")
        print("Move or delete it by hand, then re-run.")
        sys.exit(1)

    labeled = sum(1 for x in existing if isinstance(x, dict) and x.get("human_label"))

    if not labeled:
        return  # nothing worth protecting; overwrite freely

    if not FORCE:
        print(f"{path} already holds {labeled} hand-reviewed label(s) "
              f"out of {len(existing)} findings.")
        print()
        print("Rebuilding the sample would discard them, and re-labeling is "
              "hours of work — so this is refusing rather than overwriting.")
        print()
        print("  - to see the current results:  python3 evaluate_classifier.py")
        print("  - to keep reviewing:           python3 review_labels.py")
        print("  - to rebuild anyway:           python3 build_eval_sample.py --force")
        print("                                 (backs the old file up first)")
        sys.exit(1)

    backup = f"{path}.{datetime.now():%Y%m%d-%H%M%S}.bak"
    shutil.copy2(path, backup)
    print(f"--force given. Backed up {labeled} existing label(s) to {backup}\n")


guard_existing_labels(OUTPUT_PATH)

conn = pymysql.connect(
    host=DB_HOST, user=DB_USER, password=DB_PASSWORD, database=DB_NAME,
    cursorclass=pymysql.cursors.DictCursor,
)

with conn.cursor() as cur:
    cur.execute("""
        SELECT id, repo_id, tool, severity, confidence, issue_text,
               filename, line_number, code_snippet
        FROM scan_results
        WHERE tool != 'virustotal'
    """)
    rows = cur.fetchall()
conn.close()

for r in rows:
    r["severity_norm"] = normalize_severity(r["severity"] or "low")

strata = {}
for r in rows:
    key = (r["tool"], r["severity_norm"])
    strata.setdefault(key, []).append(r)

random.seed(SEED)
sample = []
print(f"{len(rows):,} candidate findings across {len(strata)} (tool, severity) strata\n")
for key in sorted(strata):
    population = strata[key]
    n = min(TARGET_PER_STRATUM, len(population))
    picked = random.sample(population, n)
    sample.extend(picked)
    print(f"  {key[0]:<12} {key[1]:<8} {n:>3} / {len(population):>7}")

for r in sample:
    r["ai_suggested_label"] = None   # "real" | "noise", filled by label_with_ai.py
    r["ai_reason"]          = None
    r["human_label"]        = None   # "real" | "noise", filled by review_labels.py

random.shuffle(sample)  # so reviewing isn't grouped tool-by-tool, which biases attention

with open(OUTPUT_PATH, "w") as f:
    json.dump(sample, f, indent=2, default=str)

print(f"\nWrote {len(sample)} findings to {OUTPUT_PATH}")
