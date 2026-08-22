"""
Recomputes risk_scores (the *current* displayed score/level for each repo)
and backfills scan_results.confidence, using the new classifier-weighted
formula, for every repo already in the DB.

scan_history is deliberately left untouched — it's a record of what was
actually reported at each past scan, and scan_results only ever holds the
most recent scan's findings (each rescan deletes and replaces them), so
there's no way to correctly recompute a past scan_history entry — the
findings behind it no longer exist. Old history entries stay on the old
scale; only new scans append new-scale entries. Run standalone; pass
--dry-run to preview without writing.
"""

import sys
import pymysql
from config import DB_HOST, DB_USER, DB_PASSWORD, DB_NAME
from scanner import score_findings, calculate_risk

DRY_RUN = "--dry-run" in sys.argv

conn = pymysql.connect(host=DB_HOST, user=DB_USER, password=DB_PASSWORD, database=DB_NAME,
                        cursorclass=pymysql.cursors.DictCursor)

updated = 0
try:
    with conn.cursor() as cur:
        cur.execute("SELECT id, repo_name, owner FROM repositories")
        repos = cur.fetchall()

    for r in repos:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT id, tool, severity, issue_text, filename, code_snippet
                FROM scan_results WHERE repo_id = %s
            """, (r["id"],))
            findings = cur.fetchall()

            findings = score_findings(findings)
            high, medium, low, score, level = calculate_risk(findings)

            cur.execute("""
                SELECT id, final_score, risk_level FROM risk_scores
                WHERE repo_id = %s ORDER BY id DESC LIMIT 1
            """, (r["id"],))
            latest = cur.fetchone()

            label = f"{r['owner']}/{r['repo_name']}"
            if latest:
                print(f"  {label}: {latest['final_score']} ({latest['risk_level']}) "
                      f"-> {score} ({level})  [{len(findings)} findings]")

            if not DRY_RUN:
                if latest:
                    cur.execute("""
                        UPDATE risk_scores
                        SET high_count=%s, medium_count=%s, low_count=%s,
                            final_score=%s, risk_level=%s
                        WHERE id=%s
                    """, (high, medium, low, score, level, latest["id"]))
                for f in findings:
                    cur.execute(
                        "UPDATE scan_results SET confidence=%s WHERE id=%s",
                        (f.get("p_real"), f["id"])
                    )
        conn.commit()
        updated += 1

    print(f"\nDone. {'Would update' if DRY_RUN else 'Updated'} {updated} repos.")

except Exception:
    conn.rollback()
    raise
finally:
    conn.close()
