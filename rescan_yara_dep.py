"""
Re-runs only YARA and dep_checker (not the full pipeline — Bandit/Semgrep/
ClamAV rows are left untouched) against every repo already in the DB, using
a fresh shallow clone. Needed because rules.yar and dep_checker.py both
changed substantively — existing scan_results rows for these two tools
reflect the OLD rules and would silently stay stale otherwise. Confidence
scores are NOT set here (that needs a retrained classifier, since YARA's
issue_text format itself changed) — run train_classifier.py and
recompute_scores.py/recompute_category_scores.py after this finishes.
"""

import os
import shutil
import subprocess
import sys
import time
import pymysql
from config import DB_HOST, DB_USER, DB_PASSWORD, DB_NAME
from scanner import extract_archives, run_yara, filter_noise
from dep_checker import check_dependencies

CLONE_DIR = "/tmp/maldet_rescan_temp"

conn = pymysql.connect(host=DB_HOST, user=DB_USER, password=DB_PASSWORD, database=DB_NAME,
                        cursorclass=pymysql.cursors.DictCursor)

with conn.cursor() as cur:
    cur.execute("SELECT id, repo_name, owner FROM repositories ORDER BY id")
    repos = cur.fetchall()

print(f"Re-scanning YARA + dep_checker for {len(repos)} repos\n")
os.makedirs(CLONE_DIR, exist_ok=True)
t0 = time.time()

for i, r in enumerate(repos, 1):
    label = f"{r['owner']}/{r['repo_name']}"
    path = os.path.join(CLONE_DIR, f"{r['owner']}_{r['repo_name']}_{r['id']}")
    if os.path.exists(path):
        shutil.rmtree(path)

    try:
        result = subprocess.run(
            ["git", "clone", "--depth=1", f"https://github.com/{r['owner']}/{r['repo_name']}.git", path],
            capture_output=True, timeout=90
        )
        if result.returncode != 0:
            print(f"[{i}/{len(repos)}] {label}: clone failed, skipping")
            continue

        extract_archives(path, "infected")
        findings = run_yara(path) + check_dependencies(path)
        findings = filter_noise(findings)

        with conn.cursor() as cur:
            cur.execute("DELETE FROM scan_results WHERE repo_id=%s AND tool IN ('yara','dep_checker')", (r["id"],))
            for f in findings:
                cur.execute("""
                    INSERT INTO scan_results (repo_id, tool, severity, issue_text, filename, line_number, code_snippet)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                """, (r["id"], f["tool"], f["severity"], f["issue_text"],
                      f["filename"], f.get("line_number", 0), f.get("code_snippet", "")))
        conn.commit()
        print(f"[{i}/{len(repos)}] {label}: {len(findings)} findings ({time.time()-t0:.0f}s elapsed)")

    except subprocess.TimeoutExpired:
        print(f"[{i}/{len(repos)}] {label}: clone timed out, skipping")
    except Exception as e:
        print(f"[{i}/{len(repos)}] {label}: ERROR {e}")
        conn.rollback()
    finally:
        if os.path.exists(path):
            shutil.rmtree(path, ignore_errors=True)

conn.close()
print(f"\nDone in {time.time()-t0:.0f}s")
