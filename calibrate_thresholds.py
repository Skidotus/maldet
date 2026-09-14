"""
Computes the new p_real-weighted score across every real repo already in
the DB, using the actual scanner.score_findings()/calculate_risk() code
path (not a reimplementation) — so the calibration matches exactly what
scan_repo() will produce. Run standalone: `python3 calibrate_thresholds.py`.
"""

import pymysql
from config import DB_HOST, DB_USER, DB_PASSWORD, DB_NAME
from scanner import score_findings, calculate_risk

conn = pymysql.connect(host=DB_HOST, user=DB_USER, password=DB_PASSWORD, database=DB_NAME,
                        cursorclass=pymysql.cursors.DictCursor)
with conn.cursor() as cur:
    cur.execute("SELECT id, repo_name, owner FROM repositories")
    repos = cur.fetchall()

    results = []
    for r in repos:
        cur.execute("""
            SELECT tool, severity, issue_text, filename, code_snippet
            FROM scan_results WHERE repo_id = %s
        """, (r["id"],))
        findings = cur.fetchall()
        if not findings:
            continue
        findings = score_findings(findings)
        high, medium, low, score, level = calculate_risk(findings)
        results.append({
            "repo": f"{r['owner']}/{r['repo_name']}",
            "n_findings": len(findings),
            "score": score,
            "level": level,
        })
conn.close()

scores = sorted(r["score"] for r in results)
n = len(scores)
print(f"{n} repos with findings\n")
print("Score distribution (percentiles):")
for p in [10, 25, 50, 75, 90, 95, 99, 100]:
    idx = min(int(n * p / 100), n - 1)
    print(f"  p{p:>3}: {scores[idx]}")

print("\nTop 15 by new score:")
for r in sorted(results, key=lambda r: -r["score"])[:15]:
    print(f"  {r['score']:>7}  {r['level']:<9} {r['n_findings']:>7} findings  {r['repo']}")

print("\nBottom 15 (excluding 0) by new score:")
nonzero = [r for r in results if r["score"] > 0]
for r in sorted(nonzero, key=lambda r: r["score"])[:15]:
    print(f"  {r['score']:>7}  {r['level']:<9} {r['n_findings']:>7} findings  {r['repo']}")

print(f"\nZero-score (Safe) repos: {sum(1 for r in results if r['score'] == 0)} / {n}")
