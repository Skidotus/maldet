"""
Exports a small slice of the live scan database as db/seed_data.sql.gz, which
docker-compose loads into a fresh MySQL container on first start (see
docker-compose.yml). Without it a teammate's first launch shows an empty
dashboard, which is a poor way to meet the project.

Deliberately a subset, not a full dump. The whole corpus is ~72MB / 235k
findings, most of it low-severity Bandit noise from a handful of very large
repos — awkward in a git repo and slow to import, for no extra insight. This
picks a spread across risk levels instead, skipping repos whose finding count
would dominate the file.

Emits INSERTs only: the schema comes from schema.sql, which MySQL applies
first (01- vs 02- filename order). Parent rows are written before child rows
so the foreign keys in schema.sql are satisfied, and original ids are
preserved so those keys still line up.

Run standalone from the project root: `python3 db/export_seed.py`
"""

import gzip
import os
import sys

import pymysql

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import DB_HOST, DB_USER, DB_PASSWORD, DB_NAME  # noqa: E402

OUTPUT_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "seed_data.sql.gz")

# Per-repo finding cap. The largest repo in the corpus carries ~157k findings
# on its own; including even one of those would balloon the file and tell a
# reader nothing that a 2k-finding repo doesn't.
MAX_FINDINGS_PER_REPO = 2500
# Roughly how many repos to aim for, spread over the five vulnerability
# levels so the dashboard shows the full Safe..Critical range.
TARGET_REPOS = 20
LEVEL_ORDER = ["Critical", "High", "Medium", "Low", "Safe"]

# Child tables in insert order. repositories is written first, separately.
CHILD_TABLES = ["risk_scores", "scan_results", "scan_history"]


def sql_literal(value):
    if value is None:
        return "NULL"
    if isinstance(value, bool):
        return "1" if value else "0"
    if isinstance(value, (int, float)):
        return repr(value)
    text = str(value)
    # Escape for a MySQL single-quoted string. Backslash first, or it would
    # double-escape the quotes added after it.
    text = (text.replace("\\", "\\\\")
                .replace("'", "\\'")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\x00", ""))
    return f"'{text}'"


def pick_repos(cur):
    """Choose repo ids spread across vulnerability levels, smallest-first
    within each level so the dump stays compact."""
    cur.execute(f"""
        SELECT r.id, r.owner, r.repo_name, rs.vuln_level, rs.malware_level,
               (SELECT COUNT(*) FROM scan_results sr WHERE sr.repo_id = r.id) AS n_findings
        FROM repositories r
        JOIN risk_scores rs ON rs.repo_id = r.id
        HAVING n_findings BETWEEN 1 AND {MAX_FINDINGS_PER_REPO}
        ORDER BY n_findings ASC
    """)
    eligible = cur.fetchall()

    by_level = {}
    for row in eligible:
        by_level.setdefault(row["vuln_level"] or "Safe", []).append(row)

    # Round-robin across levels so no single level crowds the others out.
    picked, exhausted = [], False
    while len(picked) < TARGET_REPOS and not exhausted:
        exhausted = True
        for level in LEVEL_ORDER:
            bucket = by_level.get(level) or []
            if bucket and len(picked) < TARGET_REPOS:
                picked.append(bucket.pop(0))
                exhausted = False
    return picked


def insert_statements(cur, table, repo_ids, key="repo_id"):
    """Yields one INSERT per row for `table`, restricted to repo_ids."""
    placeholders = ",".join(["%s"] * len(repo_ids))
    cur.execute(f"SELECT * FROM {table} WHERE {key} IN ({placeholders})", repo_ids)
    rows = cur.fetchall()
    if not rows:
        return 0, []

    columns = list(rows[0].keys())
    col_list = ", ".join(f"`{c}`" for c in columns)
    statements = [
        f"INSERT INTO `{table}` ({col_list}) VALUES "
        f"({', '.join(sql_literal(row[c]) for c in columns)});"
        for row in rows
    ]
    return len(rows), statements


def main():
    conn = pymysql.connect(
        host=DB_HOST, user=DB_USER, password=DB_PASSWORD, database=DB_NAME,
        cursorclass=pymysql.cursors.DictCursor,
    )
    try:
        with conn.cursor() as cur:
            picked = pick_repos(cur)
            if not picked:
                sys.exit("No eligible repos found — is the database populated?")

            repo_ids = [r["id"] for r in picked]
            print(f"Selected {len(picked)} repos "
                  f"({sum(r['n_findings'] for r in picked):,} findings total):\n")
            for r in picked:
                print(f"  {r['owner']}/{r['repo_name']:<32} "
                      f"vuln={r['vuln_level'] or '-':<9} "
                      f"malware={r['malware_level'] or '-':<9} "
                      f"{r['n_findings']:>6} findings")

            body = [
                "-- MalDet seed data — a subset of the live scan corpus.",
                "-- Generated by db/export_seed.py; loaded by docker-compose into a",
                "-- fresh MySQL container after schema.sql. INSERTs only, parents",
                "-- before children, original ids preserved so foreign keys line up.",
                "",
                "SET autocommit = 0;",
                "SET unique_checks = 0;",
                "SET foreign_key_checks = 0;",
                "",
            ]

            total = 0
            n, stmts = insert_statements(cur, "repositories", repo_ids, key="id")
            body += [f"-- repositories ({n} rows)"] + stmts + [""]
            total += n

            for table in CHILD_TABLES:
                n, stmts = insert_statements(cur, table, repo_ids)
                body += [f"-- {table} ({n} rows)"] + stmts + [""]
                total += n
                print(f"  {table}: {n:,} rows")

            body += [
                "SET foreign_key_checks = 1;",
                "SET unique_checks = 1;",
                "COMMIT;",
                "",
            ]
    finally:
        conn.close()

    with gzip.open(OUTPUT_PATH, "wt", encoding="utf-8") as f:
        f.write("\n".join(body))

    size_mb = os.path.getsize(OUTPUT_PATH) / 1024 / 1024
    print(f"\nWrote {total:,} rows to {OUTPUT_PATH} ({size_mb:.2f} MB gzipped)")


if __name__ == "__main__":
    main()
