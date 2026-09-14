"""
Consolidates duplicate (owner, repo_name) rows in `repositories`, keeping
the most-recently-scanned row per group and deleting the rest (along with
their scan_results/risk_scores/scan_history). Backed up to
pre_dedup_backup.sql / pre_dedup_scan_results_backup.sql before running.
Run standalone; pass --dry-run to preview without writing.
"""

import sys
import pymysql
from config import DB_HOST, DB_USER, DB_PASSWORD, DB_NAME

DRY_RUN = "--dry-run" in sys.argv

conn = pymysql.connect(host=DB_HOST, user=DB_USER, password=DB_PASSWORD, database=DB_NAME,
                        cursorclass=pymysql.cursors.DictCursor)

with conn.cursor() as cur:
    cur.execute("""
        SELECT owner, repo_name FROM repositories
        GROUP BY owner, repo_name HAVING COUNT(*) > 1
    """)
    groups = cur.fetchall()

print(f"{len(groups)} duplicate groups\n")

total_deleted_repos = 0
total_deleted_findings = 0

for g in groups:
    with conn.cursor() as cur:
        cur.execute("""
            SELECT id, scanned_at FROM repositories
            WHERE owner=%s AND repo_name=%s
            ORDER BY scanned_at DESC, id DESC
        """, (g["owner"], g["repo_name"]))
        rows = cur.fetchall()

    keep = rows[0]
    drop = rows[1:]
    print(f"{g['owner']}/{g['repo_name']}: keeping id={keep['id']} "
          f"(scanned_at={keep['scanned_at']}), dropping {[r['id'] for r in drop]}")

    for r in drop:
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) AS c FROM scan_results WHERE repo_id=%s", (r["id"],))
            n_findings = cur.fetchone()["c"]
            total_deleted_findings += n_findings
            total_deleted_repos += 1

            if not DRY_RUN:
                cur.execute("DELETE FROM scan_results WHERE repo_id=%s", (r["id"],))
                cur.execute("DELETE FROM risk_scores WHERE repo_id=%s", (r["id"],))
                cur.execute("DELETE FROM scan_history WHERE repo_id=%s", (r["id"],))
                cur.execute("DELETE FROM repositories WHERE id=%s", (r["id"],))

    if not DRY_RUN:
        conn.commit()

print(f"\n{'Would remove' if DRY_RUN else 'Removed'} {total_deleted_repos} duplicate repo rows "
      f"({total_deleted_findings} scan_results rows)")

conn.close()
