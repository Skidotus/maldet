"""
Backfills the vuln_*/malware_* columns on risk_scores for every repo
already in the DB, using scanner.calculate_category_risk(). scan_results
already has confidence populated (from recompute_scores.py), so this only
touches risk_scores — the blended high_count/medium_count/low_count/
final_score/risk_level columns are left as-is. Run standalone; pass
--dry-run to preview without writing.
"""

import sys
import pymysql
from config import DB_HOST, DB_USER, DB_PASSWORD, DB_NAME
from scanner import score_findings, calculate_category_risk

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
                SELECT tool, severity, issue_text, filename, code_snippet, confidence
                FROM scan_results WHERE repo_id = %s
            """, (r["id"],))
            findings = cur.fetchall()

            # confidence is already backfilled in the DB — reuse it as
            # p_real directly instead of recomputing via the classifier
            for f in findings:
                f["p_real"] = f.get("confidence")

            cat = calculate_category_risk(findings)
            vuln, malware = cat["vulnerability"], cat["malicious_pattern"]

            cur.execute("""
                SELECT id FROM risk_scores
                WHERE repo_id = %s ORDER BY id DESC LIMIT 1
            """, (r["id"],))
            latest = cur.fetchone()

            label = f"{r['owner']}/{r['repo_name']}"
            if latest:
                print(f"  {label}: vuln={vuln['score']} ({vuln['level']})  "
                      f"malware={malware['score']} ({malware['level']})")

            if not DRY_RUN and latest:
                cur.execute("""
                    UPDATE risk_scores
                    SET vuln_high=%s, vuln_medium=%s, vuln_low=%s, vuln_score=%s, vuln_level=%s,
                        malware_high=%s, malware_medium=%s, malware_low=%s, malware_score=%s, malware_level=%s
                    WHERE id=%s
                """, (vuln["high"], vuln["medium"], vuln["low"], vuln["score"], vuln["level"],
                      malware["high"], malware["medium"], malware["low"], malware["score"], malware["level"],
                      latest["id"]))
        conn.commit()
        updated += 1

    print(f"\nDone. {'Would update' if DRY_RUN else 'Updated'} {updated} repos.")

except Exception:
    conn.rollback()
    raise
finally:
    conn.close()
