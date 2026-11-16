"""
Builds the sample of findings an LLM agent labels for training.

train_classifier.py's weak labels come from rule frequency and the noise
lists, which the model then also sees as features, so it mostly relearns
that formula. This draws findings to be labelled by reading the code
instead. The labels are AI-made, not human: train_labels.jsonl records
which, and a blind human check of a subset is what measures how far they
can be trusted.

Stratified by (tool, severity) like build_eval_sample.py, with three
extra rules:
  - nothing in eval_sample.json, which stays a held-out test set
  - no semgrep finding stored as "requires login": there is no code to read
  - at most MAX_PER_RULE of one (tool, issue_text) and MAX_PER_REPO of one
    repository per stratum, so one noisy rule or one huge repo cannot fill it

Writes train_sample.json. Labels go to train_labels.jsonl, one line per
finding ({"id", "label", "reason", "labeller"}), appended batch by batch so
an interrupted run loses nothing.

    python3 build_train_sample.py            # refuses to overwrite
    python3 build_train_sample.py --force
"""

import json
import os
import random
import sys

import pymysql

from db_connect import connect
from scanner import normalize_severity

TARGET_PER_STRATUM = 40
MAX_PER_RULE = 2
MAX_PER_REPO = 6
OUTPUT_PATH = "train_sample.json"
EVAL_PATH = "eval_sample.json"
SEED = 7


def main():
    if os.path.exists(OUTPUT_PATH) and "--force" not in sys.argv:
        print(f"{OUTPUT_PATH} already exists. Labels in train_labels.jsonl refer to it; "
              f"pass --force to rebuild.")
        return 1

    held_out = set()
    if os.path.exists(EVAL_PATH):
        with open(EVAL_PATH) as fh:
            held_out = {x["id"] for x in json.load(fh)}

    db = connect()
    try:
        cur = db.cursor(pymysql.cursors.DictCursor)
        cur.execute("""
            SELECT id, repo_id, tool, severity, issue_text, filename,
                   line_number, code_snippet
            FROM scan_results
            WHERE tool NOT IN ('virustotal', 'threat_intel')
              AND (code_snippet IS NULL OR code_snippet != 'requires login')
              AND filename != ''
        """)
        rows = [r for r in cur.fetchall() if r["id"] not in held_out]
    finally:
        db.close()

    strata = {}
    for r in rows:
        r["severity_norm"] = normalize_severity(r["severity"] or "low")
        strata.setdefault((r["tool"], r["severity_norm"]), []).append(r)

    rng = random.Random(SEED)
    sample = []
    print(f"{len(rows):,} candidates in {len(strata)} strata "
          f"({len(held_out)} held out for evaluation)\n")
    for key in sorted(strata):
        population = strata[key]
        rng.shuffle(population)
        per_rule, per_repo, picked = {}, {}, []
        for r in population:
            if len(picked) == TARGET_PER_STRATUM:
                break
            rule = r["issue_text"]
            if per_rule.get(rule, 0) >= MAX_PER_RULE or per_repo.get(r["repo_id"], 0) >= MAX_PER_REPO:
                continue
            per_rule[rule] = per_rule.get(rule, 0) + 1
            per_repo[r["repo_id"]] = per_repo.get(r["repo_id"], 0) + 1
            picked.append(r)
        sample.extend(picked)
        print(f"  {key[0]:<12} {key[1]:<8} {len(picked):>3} / {len(population):>7}")

    rng.shuffle(sample)
    with open(OUTPUT_PATH, "w") as fh:
        json.dump(sample, fh, indent=2, default=str)
    print(f"\nWrote {len(sample)} findings to {OUTPUT_PATH}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
