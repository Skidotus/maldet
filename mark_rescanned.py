"""
Marks specific repos as freshly scanned — bumps repositories.scanned_at to
now and appends a scan_history row using their current risk_scores. Used
after a targeted rescan (e.g. rescan_yara_dep.py) that updates scan_results/
risk_scores directly without going through the normal scan_repo() ->
save_to_db() pipeline, which is what normally keeps scanned_at/scan_history
in sync — without this, a repo with genuinely fresh data silently doesn't
show up as recently scanned anywhere in the app. Run standalone.
"""

import sys
import pymysql
from config import DB_HOST, DB_USER, DB_PASSWORD, DB_NAME

REPO_IDS = [int(x) for x in sys.argv[1:]]
if not REPO_IDS:
    print("Usage: python3 mark_rescanned.py <repo_id> [repo_id ...]")
    sys.exit(1)

conn = pymysql.connect(host=DB_HOST, user=DB_USER, password=DB_PASSWORD, database=DB_NAME,
                        cursorclass=pymysql.cursors.DictCursor)

with conn.cursor() as cur:
    for repo_id in REPO_IDS:
        cur.execute("""
            SELECT final_score, risk_level FROM risk_scores
            WHERE repo_id=%s ORDER BY id DESC LIMIT 1
        """, (repo_id,))
        risk = cur.fetchone()
        if not risk:
            print(f"repo_id {repo_id}: no risk_scores row, skipping")
            continue

        cur.execute("UPDATE repositories SET scanned_at=NOW() WHERE id=%s", (repo_id,))
        cur.execute("""
            INSERT INTO scan_history (repo_id, risk_level, final_score)
            VALUES (%s, %s, %s)
        """, (repo_id, risk["risk_level"], risk["final_score"]))

        cur.execute("SELECT owner, repo_name FROM repositories WHERE id=%s", (repo_id,))
        r = cur.fetchone()
        print(f"{r['owner']}/{r['repo_name']} (id={repo_id}): marked scanned now, "
              f"score={risk['final_score']} ({risk['risk_level']})")

conn.commit()
conn.close()
