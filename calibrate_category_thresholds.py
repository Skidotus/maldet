"""
Computes the vulnerability and malicious_pattern axis scores across every
real repo already in the DB, using scanner.calculate_category_risk() (not a
reimplementation), to pick sensible per-axis thresholds — the two axes have
very different score scales (bandit/semgrep dominate volume), so reusing
one threshold set for both would make malware findings always look mild.
"""

import pymysql
from config import DB_HOST, DB_USER, DB_PASSWORD, DB_NAME
from scanner import score_findings, calculate_category_risk

conn = pymysql.connect(host=DB_HOST, user=DB_USER, password=DB_PASSWORD, database=DB_NAME,
                        cursorclass=pymysql.cursors.DictCursor)
with conn.cursor() as cur:
    cur.execute("SELECT id FROM repositories")
    repo_ids = [r["id"] for r in cur.fetchall()]

    vuln_scores, malware_scores = [], []
    for rid in repo_ids:
        cur.execute("""
            SELECT tool, severity, issue_text, filename, code_snippet
            FROM scan_results WHERE repo_id = %s
        """, (rid,))
        findings = cur.fetchall()
        if not findings:
            continue
        findings = score_findings(findings)
        cat = calculate_category_risk(findings)
        vuln_scores.append(cat["vulnerability"]["score"])
        malware_scores.append(cat["malicious_pattern"]["score"])
conn.close()


def report(name, scores):
    scores = sorted(scores)
    n = len(scores)
    print(f"\n{name} ({n} repos with findings)")
    for p in [10, 25, 50, 75, 90, 95, 99, 100]:
        idx = min(int(n * p / 100), n - 1)
        print(f"  p{p:>3}: {scores[idx]}")
    print(f"  zero-score: {sum(1 for s in scores if s == 0)} / {n}")


report("Vulnerability axis", vuln_scores)
report("Malicious-pattern axis", malware_scores)


def bin_counts(name, scores, low_max, med_max, high_max):
    safe = sum(1 for s in scores if s == 0)
    low  = sum(1 for s in scores if 0 < s <= low_max)
    med  = sum(1 for s in scores if low_max < s <= med_max)
    high = sum(1 for s in scores if med_max < s <= high_max)
    crit = sum(1 for s in scores if s > high_max)
    print(f"{name} <= {low_max}/{med_max}/{high_max}: "
          f"Safe={safe} Low={low} Medium={med} High={high} Critical={crit}")


print()
for lo, me, hi in [(15, 60, 250), (20, 80, 300), (10, 40, 150)]:
    bin_counts("vuln  ", vuln_scores, lo, me, hi)

print()
for lo, me, hi in [(3, 12, 40), (2, 8, 30), (5, 15, 50)]:
    bin_counts("malware", malware_scores, lo, me, hi)
