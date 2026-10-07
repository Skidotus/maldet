"""
Fills in risk_scores.llm_summary for repos that don't have one yet, without
rescanning anything.

Why this exists: the 4GB VPS cannot host the LLM. qwen3.5:2b peaks around 3GB
and semgrep alone peaks near 2GB, so the deployment runs with
MALDET_OLLAMA_DISABLE=1 and renders the rule-based summary. This script runs
somewhere that *can* host the model -- a laptop -- and writes the summaries
back into the same database afterwards. Nothing requires the host that
scanned a repo to be the host that explains it.

    # reach the VPS database through an SSH tunnel
    ssh -fN -L 3307:127.0.0.1:3306 user@your-vps
    DB_PORT=3307 python3 backfill_summaries.py --limit 20

Grouping happens in SQL on purpose. A summary needs the top ~15
(tool, issue_text) groups, not every finding, and some repos have six figures
of findings -- one has ~157k. Aggregating server-side turns that into a few
dozen rows per repo, which is the difference between tens of megabytes and
about one over a phone hotspot.

Safe to interrupt and re-run: each repo is committed as it completes, and
only repos still missing a summary are picked up unless --force is given.
"""

import argparse
import sys
import time

import pymysql

import llm_summary
from db_connect import connect, describe
from scanner import finding_category

# Mirrors llm_summary.SEVERITY_WEIGHT, expressed as a SQL rank so the worst
# severity in a group can be found with MAX().
SEVERITY_RANK_SQL = "CASE severity WHEN 'high' THEN 3 WHEN 'medium' THEN 2 ELSE 1 END"
RANK_TO_SEVERITY = {3: "high", 2: "medium", 1: "low"}


def repos_needing_summary(cur, only_repo=None, force=False, limit=None):
    """Repos with findings and no stored summary, worst risk first."""
    where = ["EXISTS (SELECT 1 FROM scan_results s WHERE s.repo_id = r.id)"]
    params = []
    if not force:
        where.append("(rs.llm_summary IS NULL OR rs.llm_summary = '')")
    if only_repo:
        where.append("CONCAT(r.owner, '/', r.repo_name) = %s")
        params.append(only_repo)

    sql = f"""
        SELECT r.id, CONCAT(r.owner, '/', r.repo_name) AS full_name,
               rs.vuln_score, rs.vuln_level, rs.malware_score, rs.malware_level,
               rs.risk_level
        FROM repositories r
        JOIN risk_scores rs ON rs.repo_id = r.id
        WHERE {' AND '.join(where)}
        ORDER BY rs.final_score DESC
    """
    if limit:
        sql += " LIMIT %s"
        params.append(int(limit))
    cur.execute(sql, params)
    return cur.fetchall()


def grouped_findings(cur, repo_id):
    """(groups, total_findings) for one repo, aggregated by the database.

    Returns groups in the shape llm_summary._select_groups() expects, so the
    same quota logic applies here as at scan time.
    """
    # GROUP_CONCAT gives the example from the worst instance rather than an
    # arbitrary row. Only the first element is read, and truncation only ever
    # affects the tail, so a modest max_len is safe.
    cur.execute("SET SESSION group_concat_max_len = 1024")
    cur.execute(f"""
        SELECT tool,
               -- COLLATE utf8mb4_bin, because the column's own collation is
               -- utf8mb4_0900_ai_ci -- case- and accent-insensitive. Python
               -- dict keys are not, so MySQL merged groups that
               -- _rank_groups() keeps apart: 17 issue_texts corpus-wide,
               -- including "Possible hardcoded password: 'abc'" with
               -- "...'ABC'", which are different hardcoded passwords.
               issue_text COLLATE utf8mb4_bin AS issue_text,
               COUNT(*)                        AS count,
               MAX({SEVERITY_RANK_SQL})        AS sev_rank,
               -- MAX(confidence), not MAX(COALESCE(confidence, 1.0)):
               -- COALESCE with a decimal literal promotes the FLOAT column
               -- to double, so 0.4406 comes back as 0.4406000077724457 and
               -- near-tied groups then sort differently from the scan-time
               -- path. NULLs are counted separately instead and folded in
               -- below, reproducing _rank_groups()' "NULL means 1.0".
               MAX(confidence)                 AS confidence,
               SUM(confidence IS NULL)         AS null_conf,
               SUBSTRING_INDEX(GROUP_CONCAT(
                   CONCAT(COALESCE(filename, ''), 0x1e, COALESCE(line_number, 0))
                   ORDER BY {SEVERITY_RANK_SQL} DESC, confidence DESC,
                            -- utf8mb4_bin so the tie-break orders by byte,
                            -- the way Python compares strings. Under the
                            -- column's case-insensitive collation 'C' sorts
                            -- after 'a', so MySQL picked acceslibre.py where
                            -- Python picked CONTRIBUTING.md from the same
                            -- group.
                            COALESCE(filename, '') COLLATE utf8mb4_bin ASC,
                            COALESCE(line_number, 0) ASC
                   SEPARATOR 0x1f), 0x1f, 1)   AS example
        FROM scan_results
        WHERE repo_id = %s
        GROUP BY tool, issue_text COLLATE utf8mb4_bin
    """, (repo_id,))

    # SQL groups on the raw issue_text; the merge below re-keys on the
    # stripped text. MySQL's TRIM() removes spaces only, while
    # _rank_groups() uses Python's .strip(), which also removes newlines,
    # tabs and carriage returns -- so trimming in SQL still left groups
    # split here that are merged at scan time. Doing it in Python makes the
    # two paths key identically, and costs nothing: the rows are already
    # aggregated, so this merges a handful of them.
    merged, total = {}, 0
    for row in cur.fetchall():
        example_file, _, example_line = (row["example"] or "").partition("\x1e")
        issue_text = (row["issue_text"] or "").strip()
        severity   = RANK_TO_SEVERITY.get(int(row["sev_rank"] or 1), "low")
        # Explicit None check, NOT `row["confidence"] or 1.0`: a stored
        # confidence of 0.0 is falsy, so `or` rewrote "the classifier is
        # certain this is noise" into "certain it is real" and sent the
        # finding to the top of the ranking. 38 findings in django alone.
        # Any NULL in the group means _rank_groups() saw a 1.0 for that
        # finding, and 1.0 is the maximum, so the group's confidence is 1.0.
        if int(row["null_conf"] or 0) > 0 or row["confidence"] is None:
            confidence = 1.0
        else:
            confidence = float(row["confidence"])
        count      = int(row["count"])
        total     += count

        key = (row["tool"], issue_text)
        g = merged.get(key)
        if g is None:
            merged[key] = {
                "tool":         row["tool"],
                "issue_text":   issue_text,
                "count":        count,
                "severity":     severity,
                "confidence":   confidence,
                "example_file": example_file,
                "example_line": int(example_line) if example_line.isdigit() else 0,
                "snippet":      "",
                # finding_category() reads tool and issue_text, which is all
                # the dep_checker CVE special case needs.
                "category":     finding_category({"tool": row["tool"],
                                                  "issue_text": issue_text}),
            }
            continue

        # Same merge rule _rank_groups() uses: worst severity and highest
        # confidence tracked independently, example chosen on severity first
        # with confidence as the tie-break.
        g["count"] += count
        if llm_summary.SEVERITY_WEIGHT.get(severity, 1) > \
           llm_summary.SEVERITY_WEIGHT.get(g["severity"], 1):
            g["severity"] = severity
        if (llm_summary.SEVERITY_WEIGHT.get(severity, 1), confidence) > \
           (llm_summary.SEVERITY_WEIGHT.get(g["severity"], 1), g["confidence"]):
            g["example_file"] = example_file
            g["example_line"] = int(example_line) if example_line.isdigit() else 0
        g["confidence"] = max(g["confidence"], confidence)

    groups = list(merged.values())

    # Same ordering llm_summary._rank_groups() produces, so "top" means the
    # same thing it means at scan time.
    # Same key, including the tie-break, as llm_summary._rank_groups().
    groups.sort(
        key=lambda g: (-(llm_summary.SEVERITY_WEIGHT.get(g["severity"], 1)
                         * max(g["confidence"], 0.01)),
                       g["tool"], g["issue_text"]),
    )
    return groups, total


def main():
    ap = argparse.ArgumentParser(description=__doc__.strip().split("\n")[0])
    ap.add_argument("--limit", type=int, help="stop after this many repos")
    ap.add_argument("--repo", help="a single owner/name")
    ap.add_argument("--force", action="store_true",
                    help="regenerate even where a summary already exists")
    ap.add_argument("--dry-run", action="store_true",
                    help="show what would be done, generate nothing, write nothing")
    ap.add_argument("--show", action="store_true", help="print each summary")
    args = ap.parse_args()

    # Stated up front because the whole point of DB_PORT is that it changes
    # which database this writes to.
    print(f"database : {describe()}")
    print(f"model    : {llm_summary.OLLAMA_MODEL} at {llm_summary.OLLAMA_HOST}")

    if not args.dry_run and not llm_summary.is_available():
        print("\nOllama is not reachable, or does not have that model.")
        print("Nothing written. Start it and re-run:  systemctl --user start ollama")
        return 1

    db = connect(autocommit=True)
    try:
        cur = db.cursor(pymysql.cursors.DictCursor)

        targets = repos_needing_summary(cur, args.repo, args.force, args.limit)
        print(f"repos to summarise: {len(targets)}\n")
        if not targets:
            print("Nothing to do.")
            return 0

        done = failed = 0
        for i, repo in enumerate(targets, 1):
            groups, total = grouped_findings(cur, repo["id"])
            label = f"[{i}/{len(targets)}] {repo['full_name']}"
            if not groups:
                print(f"{label}: no findings, skipped")
                continue

            mal = sum(1 for g in groups if g["category"] == "malicious_pattern")
            print(f"{label}  {total:,} findings in {len(groups)} groups "
                  f"({mal} malware)  risk={repo['risk_level']}")

            if args.dry_run:
                continue

            started = time.time()
            text = llm_summary.summarize_groups(
                repo["full_name"], groups, total,
                {"level": repo["vuln_level"],    "score": repo["vuln_score"]},
                {"level": repo["malware_level"], "score": repo["malware_score"]},
            )
            if not text:
                print(f"    no summary produced ({time.time()-started:.0f}s), leaving as-is")
                failed += 1
                continue

            cur.execute("UPDATE risk_scores SET llm_summary = %s WHERE repo_id = %s",
                        (text, repo["id"]))
            done += 1
            print(f"    stored {len(text)} chars in {time.time()-started:.0f}s")
            if args.show:
                print(f"    {text}\n")

        print(f"\nwritten: {done}   not produced: {failed}")
        return 0
    finally:
        db.close()


if __name__ == "__main__":
    sys.exit(main())
