"""
Scores the LLM summaries against checks, instead of against an opinion.

NOTES.md put the problem plainly: the model was chosen by reading output for
two repositories, which is enough to pick a default and not enough for the
report to claim a method. This is the method -- a stratified sample across
the risk levels, with every check mechanical and re-runnable.

What it checks, and why each one is a real failure mode rather than a guess:

  fabricated_numbers   Every number in the summary should appear in the
                       prompt. llama3.2 wrote "a score of 426.0 out of 1000"
                       for a scale that does not exist; nothing in the prompt
                       mentions 1000. This catches that class directly.
  invented_scale       "out of N", "N/100" -- the scores are unbounded, so
                       any maximum is invented.
  fabricated_files     Any path-looking token must appear in the prompt. The
                       prompt names an example file per finding group, so a
                       path the model produced itself is made up.
  fabricated_ids       CVE-/PYSEC-/GHSA- identifiers must appear in the
                       prompt. An invented advisory id is the most damaging
                       possible fabrication in a security tool.
  fabricated_tools     Naming a detector that did not report anything here.
  contradicts_risk     Calling a Critical repo safe to use, or a Safe repo
                       malicious. The prompt states the levels as settled and
                       forbids re-rating them, so this is the instruction
                       most worth testing.
  format_*             3-5 sentences, one paragraph, no markdown. Stated in
                       the prompt, so a breach is instruction-following
                       failure -- and markdown renders literally on the
                       detail page, which looks like a bug in the app.

Usage:

    python3 evaluate_summaries.py --stored            # score what is in the DB
    python3 evaluate_summaries.py --generate -n 20    # fresh sample, needs Ollama
    python3 evaluate_summaries.py --generate -n 20 --model granite4.2:3b

Writes summary_eval.json so a run is citable, and prints the rates.
"""

import argparse
import json
import os
import re
import sys
import time
from collections import Counter

import pymysql

import llm_summary
from backfill_summaries import grouped_findings
from db_connect import connect, describe

OUTPUT_PATH = "summary_eval.json"

# Detector names the model could plausibly claim. Checked against the prompt,
# so naming one that did not fire here counts as fabricated.
KNOWN_TOOLS = ["bandit", "semgrep", "yara", "clamav", "guarddog",
               "pip-audit", "virustotal", "dependabot", "snyk", "sonarqube",
               "trivy", "codeql", "checkmarx", "veracode"]

# Phrases that assert a repo is fine, and phrases that assert deliberate
# malice. Used only against the stated level, never to judge the repo.
# Claims about the repository as a whole, only. "nothing concerning", "no
# real concerns" and "no cause for concern" were dropped: they are routinely
# scoped to one aspect ("no cause for concern about the build scripts"),
# which is a fair thing to say about a Critical repo and not a contradiction.
# This check is deliberately tuned for precision over recall -- a checker
# that flags correct summaries gets ignored, and then it catches nothing.
SAFE_CLAIMS = [
    "safe to use", "is safe", "no security issues", "poses no risk",
    "appears to be safe", "can be used safely", "no significant risk",
]
# Deliberately assertive forms only. A bare "malicious intent" is useless as
# a trigger: it occurs just as often in denials ("rather than malicious
# intent") and in hedges ("some signs of potentially malicious intent") as in
# claims, and matching it flagged two summaries that were saying the opposite.
MALICE_CLAIMS = [
    "is intentionally malicious", "intentionally malicious code",
    "deliberately malicious", "is malware", "contains malware",
    "written with malicious intent", "designed to harm", "clearly malicious",
]

# Words just before a phrase that invert or defuse it. Checked over a window
# rather than parsed: "before it can be used safely" and "no cause for
# concern" both contain their phrase while asserting the opposite, and a
# substring match alone cannot tell those apart from the real thing.
NEGATORS = [
    "not ", "n't", "no ", "never", "before", "rather than", "instead of",
    "unless", "until", "without", "than ", "far from", "cannot", "can not",
    "hardly", "unlikely",
]
HEDGES = [
    "potentially", "possibly", "may be", "might be", "could be", "some signs",
    "signs of", "suggests", "appears to", "seems to", "if ",
]

SENTENCE_SPLIT = re.compile(r"(?<=[.!?])\s+")
NUMBER = re.compile(r"\d+(?:\.\d+)?")
PATHISH = re.compile(r"[\w./-]*/[\w./-]+\.\w{1,5}|\b[\w-]+\.(?:py|js|ts|php|rb|go|java|sh|yml|yaml|json|toml|lock|txt|md)\b")
ADVISORY = re.compile(r"\b(?:CVE|PYSEC|GHSA)[-‑][\w.-]+", re.I)
MARKDOWN = re.compile(r"`|\*\*|^\s*[-*+]\s|^\s*#{1,6}\s", re.M)


def _norm(text):
    """Lowercased, with the typographic characters some models emit folded
    down, so a comparison against the prompt is not defeated by a
    non-breaking hyphen."""
    return (text.lower()
            .replace("‑", "-").replace("–", "-").replace("—", "-")
            .replace("’", "'").replace(" ", " "))


def _asserts(text, phrases, window=70):
    """Phrases the summary actually claims, ignoring negated or hedged ones.

    A substring match is not a claim. "before it can be used safely" contains
    "can be used safely" while saying the repo is *not* safe yet, and "some
    signs of potentially malicious intent" is a hedge, not an accusation.
    Both were flagged as contradictions on the first run of this script,
    against summaries that were correct -- so the window before each match is
    inspected for anything that inverts or softens it.
    """
    claimed = []
    for phrase in phrases:
        for m in re.finditer(re.escape(phrase), text):
            before = text[max(0, m.start() - window):m.start()]
            if any(w in before for w in NEGATORS) or any(w in before for w in HEDGES):
                continue
            claimed.append(phrase)
            break
    return claimed


def check(summary, prompt, vuln_level, malware_level):
    """Every check for one summary. Returns {name: True} where True == failed."""
    s, p = _norm(summary), _norm(prompt)
    failures = {}

    nums_in_prompt = set(NUMBER.findall(p))
    bad_nums = [n for n in NUMBER.findall(s) if n not in nums_in_prompt]
    if bad_nums:
        failures["fabricated_numbers"] = bad_nums[:5]

    scale = re.findall(r"out of \d+|\d+\s*/\s*(?:100|1000)|\bon a scale\b", s)
    if scale:
        failures["invented_scale"] = scale[:3]

    bad_paths = [m for m in set(PATHISH.findall(s)) if m not in p]
    if bad_paths:
        failures["fabricated_files"] = bad_paths[:5]

    bad_ids = [m for m in set(ADVISORY.findall(s)) if m not in p]
    if bad_ids:
        failures["fabricated_ids"] = bad_ids[:5]

    bad_tools = [t for t in KNOWN_TOOLS if t in s and t not in p]
    if bad_tools:
        failures["fabricated_tools"] = bad_tools

    # Contradiction is judged only against the levels the prompt stated.
    worst = max(vuln_level, malware_level,
                key=lambda l: ["Safe", "Low", "Medium", "High", "Critical"].index(l)
                if l in ("Safe", "Low", "Medium", "High", "Critical") else 0)
    if worst in ("High", "Critical"):
        hit = _asserts(s, SAFE_CLAIMS)
        if hit:
            failures["contradicts_risk"] = f"{worst} repo described as: {hit[:2]}"
    if malware_level in ("Safe", "Low"):
        hit = _asserts(s, MALICE_CLAIMS)
        if hit:
            failures["contradicts_risk"] = f"malware={malware_level} but claims: {hit[:2]}"

    sentences = [x for x in SENTENCE_SPLIT.split(summary.strip()) if x.strip()]
    if not 3 <= len(sentences) <= 5:
        failures["format_sentence_count"] = len(sentences)
    if MARKDOWN.search(summary):
        failures["format_markdown"] = MARKDOWN.findall(summary)[:3]
    if "\n\n" in summary.strip():
        failures["format_multi_paragraph"] = True
    if summary.strip() and summary.strip()[-1] not in ".!?":
        failures["format_truncated"] = summary.strip()[-40:]

    return failures


def sample(cur, n, stored_only):
    """A stratified sample across risk levels, so the result is not dominated
    by whichever level happens to be most common in the corpus."""
    having = "rs.llm_summary IS NOT NULL" if stored_only else \
             "EXISTS (SELECT 1 FROM scan_results s WHERE s.repo_id = r.id)"
    cur.execute(f"""
        SELECT r.id, CONCAT(r.owner,'/',r.repo_name) AS full_name,
               rs.risk_level, rs.vuln_level, rs.vuln_score,
               rs.malware_level, rs.malware_score, rs.llm_summary
        FROM repositories r JOIN risk_scores rs ON rs.repo_id = r.id
        WHERE {having}
        ORDER BY rs.final_score DESC
    """)
    rows = cur.fetchall()
    by_level = {}
    for r in rows:
        by_level.setdefault(r["risk_level"] or "Unknown", []).append(r)
    picked, i = [], 0
    while len(picked) < n and any(by_level.values()):
        for lvl in sorted(by_level):
            if by_level[lvl] and len(picked) < n:
                picked.append(by_level[lvl].pop(0))
        i += 1
        if i > n + 5:
            break
    return picked


def main():
    ap = argparse.ArgumentParser(description=__doc__.strip().split("\n")[0])
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--stored", action="store_true",
                   help="score summaries already in the database (no model needed)")
    g.add_argument("--generate", action="store_true",
                   help="generate fresh summaries for the sample (needs Ollama)")
    ap.add_argument("-n", type=int, default=20, help="sample size (default 20)")
    ap.add_argument("--model", help="override MALDET_OLLAMA_MODEL for this run")
    ap.add_argument("--out", default=OUTPUT_PATH)
    args = ap.parse_args()

    if args.model:
        os.environ["MALDET_OLLAMA_MODEL"] = args.model
        llm_summary.OLLAMA_MODEL = args.model

    print(f"database : {describe()}")
    print(f"mode     : {'stored' if args.stored else 'generate'}")
    if args.generate:
        print(f"model    : {llm_summary.OLLAMA_MODEL}")
        if not llm_summary.is_available():
            print("\nOllama is not reachable, or lacks that model. Nothing to do.")
            return 1

    db = connect(autocommit=True)
    try:
        cur = db.cursor(pymysql.cursors.DictCursor)
        rows = sample(cur, args.n, args.stored)
        print(f"sample   : {len(rows)} repos\n")
        if not rows:
            print("No repos match. With --stored, run backfill_summaries.py first.")
            return 1

        results, failed_counter = [], Counter()
        for i, r in enumerate(rows, 1):
            groups, total = grouped_findings(cur, r["id"])
            if not groups:
                continue
            vuln    = {"level": r["vuln_level"],    "score": r["vuln_score"]}
            malware = {"level": r["malware_level"], "score": r["malware_score"]}
            prompt  = llm_summary._compose_prompt(r["full_name"], groups, total,
                                                  vuln, malware)
            if args.stored:
                text, took = r["llm_summary"], 0.0
            else:
                t0 = time.time()
                text = llm_summary.summarize_groups(r["full_name"], groups, total,
                                                    vuln, malware)
                took = time.time() - t0

            if not text:
                print(f"[{i}/{len(rows)}] {r['full_name']:38s} NO SUMMARY")
                failed_counter["no_summary"] += 1
                results.append({"repo": r["full_name"], "risk": r["risk_level"],
                                "summary": None, "failures": {"no_summary": True},
                                "seconds": round(took, 1)})
                continue

            failures = check(text, prompt, r["vuln_level"] or "Safe",
                             r["malware_level"] or "Safe")
            for k in failures:
                failed_counter[k] += 1
            mark = "ok  " if not failures else "FAIL"
            print(f"[{i}/{len(rows)}] {mark} {r['full_name']:38s} "
                  f"{r['risk_level']:8s} {took:5.1f}s "
                  f"{','.join(failures) if failures else ''}")
            results.append({"repo": r["full_name"], "risk": r["risk_level"],
                            "vuln_level": r["vuln_level"],
                            "malware_level": r["malware_level"],
                            "summary": text, "failures": failures,
                            "seconds": round(took, 1)})

        scored = [x for x in results if x["summary"]]
        clean  = [x for x in scored if not x["failures"]]
        print(f"\n{'-'*58}")
        print(f"summaries scored : {len(scored)}")
        print(f"fully clean      : {len(clean)}"
              + (f"  ({len(clean)/len(scored)*100:.0f}%)" if scored else ""))
        print(f"\nfailures by check ({len(scored)} summaries):")
        for name, n in failed_counter.most_common():
            print(f"  {name:24s} {n:3d}  ({n/max(len(scored),1)*100:.0f}%)")
        if not failed_counter:
            print("  none")

        out = {"model": llm_summary.OLLAMA_MODEL,
               "mode": "stored" if args.stored else "generate",
               "scored": len(scored), "clean": len(clean),
               "failures_by_check": dict(failed_counter),
               "results": results}
        with open(args.out, "w") as f:
            json.dump(out, f, indent=2)
        print(f"\nwritten to {args.out}")
        return 0
    finally:
        db.close()


if __name__ == "__main__":
    sys.exit(main())
